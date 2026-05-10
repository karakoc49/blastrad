package gitlab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer sets up a test HTTP server that simulates the real GitLab API.
//
// httptest.NewServer comes from the Go standard library — no extra dependency.
func newTestServer(t *testing.T, routes map[string]interface{}) (*httptest.Server, *Client) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token check — behave like the real API
		if r.Header.Get("PRIVATE-TOKEN") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return the correct response based on URL path.
		// Ignore pagination parameters (page, per_page).
		path := r.URL.Path

		data, ok := routes[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// X-Next-Page empty → single page, pagination complete
		w.Header().Set("X-Next-Page", "")
		json.NewEncoder(w).Encode(data)
	}))

	client := NewClient(server.URL, "test-token-123")
	return server, client
}

func TestFetchVariables(t *testing.T) {
	// Simulated GitLab API response
	fakeVariables := []map[string]interface{}{
		{
			"key":               "K8S_TOKEN",
			"value":             "secret-value",
			"protected":         false, // ISSUE: not protected
			"masked":            true,
			"environment_scope": "*",
		},
		{
			"key":               "DB_PASSWORD",
			"value":             "db-secret",
			"protected":         true,
			"masked":            false, // ISSUE: not masked, visible in logs
			"environment_scope": "production",
		},
		{
			"key":               "APP_VERSION",
			"value":             "1.0.0",
			"protected":         false,
			"masked":            false,
			"environment_scope": "*",
		},
	}

	server, client := newTestServer(t, map[string]interface{}{
		"/api/v4/projects/42/variables": fakeVariables,
	})
	defer server.Close()

	fetcher := NewFetcher(client, "42")
	vars, err := fetcher.FetchVariables()
	if err != nil {
		t.Fatalf("FetchVariables error: %v", err)
	}

	if len(vars) != 3 {
		t.Errorf("expected 3 variables, got %d", len(vars))
	}

	// K8S_TOKEN should have protected=false
	k8sToken := findVariable(vars, "K8S_TOKEN")
	if k8sToken == nil {
		t.Fatal("K8S_TOKEN not found")
	}
	if k8sToken.Protected {
		t.Error("K8S_TOKEN should have protected=false")
	}
}

func TestUnprotectedSecrets(t *testing.T) {
	variables := []Variable{
		{Key: "K8S_TOKEN", Protected: false, Masked: true},
		{Key: "DB_PASSWORD", Protected: true, Masked: false},
		{Key: "LOG_LEVEL", Protected: false, Masked: false},
	}

	// K8S_TOKEN and LOG_LEVEL are not protected → both are risky
	risky := UnprotectedSecrets(variables)
	if len(risky) != 2 {
		t.Errorf("expected 2 unprotected secrets, got %d", len(risky))
	}
}

func TestIsEnvironmentProtected(t *testing.T) {
	protected := []ProtectedEnvironment{
		{Name: "production"},
		{Name: "staging"},
	}

	// production should be protected
	if !IsEnvironmentProtected("production", protected) {
		t.Error("production should be protected")
	}

	// review/feature-x should not be protected
	if IsEnvironmentProtected("review/feature-x", protected) {
		t.Error("review/feature-x should not be protected")
	}
}

func TestHasSharedRunners(t *testing.T) {
	runners := []Runner{
		{ID: 1, Shared: true, Active: true, Paused: false, Description: "shared-runner-01"},
		{ID: 2, Shared: false, Active: true, Paused: false, Description: "project-runner-01"},
	}

	if !HasSharedRunners(runners) {
		t.Error("should have a shared runner")
	}

	// Only specific runner
	onlySpecific := []Runner{
		{ID: 2, Shared: false, Active: true, Paused: false},
	}
	if HasSharedRunners(onlySpecific) {
		t.Error("should not have a shared runner")
	}
}

func TestFetchAll(t *testing.T) {
	server, client := newTestServer(t, map[string]interface{}{
		"/api/v4/projects/42": map[string]interface{}{
			"id":                  42,
			"name":                "test-project",
			"path_with_namespace": "mygroup/test-project",
		},
		"/api/v4/projects/42/variables": []map[string]interface{}{
			{"key": "SECRET", "protected": false, "masked": true, "environment_scope": "*"},
		},
		"/api/v4/projects/42/environments": []map[string]interface{}{
			{"id": 1, "name": "production", "state": "available"},
		},
		"/api/v4/projects/42/protected_environments": []map[string]interface{}{},
		"/api/v4/projects/42/runners": []map[string]interface{}{
			{"id": 1, "is_shared": true, "active": true, "paused": false},
		},
	})
	defer server.Close()

	fetcher := NewFetcher(client, "42")
	info, err := fetcher.FetchAll()
	if err != nil {
		t.Fatalf("FetchAll error: %v", err)
	}

	if info.Project.Name != "test-project" {
		t.Errorf("expected project name 'test-project', got '%s'", info.Project.Name)
	}
	if len(info.Variables) != 1 {
		t.Errorf("expected 1 variable, got %d", len(info.Variables))
	}
	if len(info.Environments) != 1 {
		t.Errorf("expected 1 environment, got %d", len(info.Environments))
	}
	if !HasSharedRunners(info.Runners) {
		t.Error("should have a shared runner")
	}
}

// findVariable is a helper that searches a variable list by key name.
func findVariable(vars []Variable, key string) *Variable {
	for i, v := range vars {
		if v.Key == key {
			return &vars[i]
		}
	}
	return nil
}
