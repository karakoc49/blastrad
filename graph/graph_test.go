package graph

import (
	"testing"

	gitlabcollector "github.com/karakoc49/blastrad/collector/gitlab"
	"github.com/karakoc49/blastrad/collector/parser"
)

// buildTestPipeline builds a sample pipeline for testing.
// This pipeline has a security vulnerability:
// fork MR → deploy-production → K8S_TOKEN (protected=false)
func buildTestPipeline() *parser.Pipeline {
	return &parser.Pipeline{
		Stages: []string{"build", "test", "deploy"},
		Variables: map[string]string{
			"APP_ENV": "production",
		},
		Jobs: map[string]*parser.Job{
			"build-app": {
				Name:  "build-app",
				Stage: "build",
				Tags:  []string{"shared"},
				Rules: []parser.Rule{
					{If: "$CI_MERGE_REQUEST_IID", When: "always"},
					{If: "$CI_COMMIT_BRANCH == \"main\"", When: "always"},
				},
			},
			"deploy-production": {
				Name:  "deploy-production",
				Stage: "deploy",
				Tags:  []string{"shared"},
				Variables: map[string]string{
					"K8S_TOKEN": "$KUBE_PROD_TOKEN",
				},
				Environment: &parser.Environment{
					Name: "production",
				},
				// CRITICAL: fork MRs can also trigger this job
				Rules: []parser.Rule{
					{If: "$CI_MERGE_REQUEST_IID", When: "always"},
					{If: "$CI_COMMIT_BRANCH == \"main\"", When: "always"},
				},
				Needs: []parser.Need{
					{Job: "build-app"},
				},
			},
		},
	}
}

// buildTestProjectInfo builds a sample GitLab API response for testing.
func buildTestProjectInfo() *gitlabcollector.ProjectInfo {
	return &gitlabcollector.ProjectInfo{
		Project: &gitlabcollector.Project{
			ID:   42,
			Name: "test-project",
		},
		Variables: []gitlabcollector.Variable{
			{
				Key:              "K8S_TOKEN",
				Protected:        false, // ISSUE: visible to fork MRs
				Masked:           true,
				EnvironmentScope: "*",
			},
			{
				Key:              "APP_ENV",
				Protected:        false,
				Masked:           false,
				EnvironmentScope: "*",
			},
		},
		Environments: []gitlabcollector.Environment{
			{ID: 1, Name: "production", State: "available"},
		},
		ProtectedEnvironments: []gitlabcollector.ProtectedEnvironment{},
		// Production environment is UNPROTECTED
		Runners: []gitlabcollector.Runner{
			{ID: 1, Description: "shared-runner-01", Shared: true, Active: true, Paused: false,
				TagList: []string{"shared"}},
		},
	}
}

// TestBuild tests whether the graph builder works correctly.
func TestBuild(t *testing.T) {
	pipeline := buildTestPipeline()
	info := buildTestProjectInfo()

	g, err := Build(pipeline, info)
	if err != nil {
		t.Fatalf("graph build error: %v", err)
	}

	// Were nodes added?
	t.Run("NodeCount", func(t *testing.T) {
		// Expected nodes:
		// triggers: merge_request_event, push (2)
		// jobs: build-app, deploy-production (2)
		// secrets: K8S_TOKEN, APP_ENV (2)
		// environments: production (1)
		// runners: shared-runner-01 (1)
		// Total: 8
		if g.NodeCount() < 6 {
			t.Errorf("expected at least 6 nodes, got %d", g.NodeCount())
		}
	})

	// Does the deploy-production job node exist?
	t.Run("JobNodes", func(t *testing.T) {
		node, ok := g.GetNode("job:deploy-production")
		if !ok {
			t.Fatal("deploy-production job node not found")
		}
		if node.Type != NodeTypeJob {
			t.Error("node type should be Job")
		}
	})

	// Does the K8S_TOKEN secret node exist and is it critical?
	t.Run("SecretNodes", func(t *testing.T) {
		node, ok := g.GetNode("secret:K8S_TOKEN")
		if !ok {
			t.Fatal("K8S_TOKEN secret node not found")
		}
		// Should be critical because protected=false
		if node.Criticality != CriticalityCritical {
			t.Errorf("K8S_TOKEN criticality should be CRITICAL, got %s", node.Criticality)
		}
	})

	// Is the merge_request_event trigger untrusted?
	t.Run("TriggerTrust", func(t *testing.T) {
		node, ok := g.GetNode("trigger:merge_request_event")
		if !ok {
			t.Fatal("merge_request_event trigger node not found")
		}
		if node.Trust != TrustUntrusted {
			t.Error("merge_request_event trigger should be UNTRUSTED")
		}
	})

	// Were edges created correctly?
	t.Run("EdgeCount", func(t *testing.T) {
		if g.EdgeCount() == 0 {
			t.Error("expected at least some edges")
		}
	})
}

// TestAnalyzer tests whether the analyzer produces correct findings.
func TestAnalyzer(t *testing.T) {
	pipeline := buildTestPipeline()
	info := buildTestProjectInfo()

	g, err := Build(pipeline, info)
	if err != nil {
		t.Fatalf("graph build error: %v", err)
	}

	analyzer := NewAnalyzer(g)
	findings := analyzer.Analyze()

	t.Logf("Found %d security finding(s):", len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s", f.Severity, f.Title)
		t.Logf("    Path: %v", f.PathNames)
		t.Logf("    Description: %s", f.Description)
	}

	// Should have at least one finding
	if len(findings) == 0 {
		t.Error("expected at least one finding for this vulnerable pipeline")
	}

	// Should have a CRITICAL or HIGH severity finding
	t.Run("SeverityCheck", func(t *testing.T) {
		hasCritical := false
		for _, f := range findings {
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				hasCritical = true
				break
			}
		}
		if !hasCritical {
			t.Error("expected a CRITICAL or HIGH finding for this pipeline")
		}
	})

	// Are findings sorted by severity?
	t.Run("SortOrder", func(t *testing.T) {
		order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
		for i := 1; i < len(findings); i++ {
			if order[findings[i-1].Severity] > order[findings[i].Severity] {
				t.Error("findings are not sorted by severity")
				break
			}
		}
	})
}

// TestBlastRadius tests the blast radius calculation.
func TestBlastRadius(t *testing.T) {
	g := New()

	// Build a simple graph:
	// job:deploy → secret:K8S_TOKEN (critical)
	//           → env:production (critical)
	g.AddNode(NewJobNode("deploy", "deploy"))
	g.AddNode(NewSecretNode("K8S_TOKEN", false, true))
	g.AddNode(NewEnvironmentNode("production", false))

	g.AddEdge("job:deploy", "secret:K8S_TOKEN", EdgeReadsSecret)
	g.AddEdge("job:deploy", "env:production", EdgeDeploysTo)

	radius := calculateBlastRadius(g, "job:deploy")

	// 2 critical nodes are reachable from the deploy job
	if radius < 2 {
		t.Errorf("blast radius should be at least 2, got %d", radius)
	}
}
