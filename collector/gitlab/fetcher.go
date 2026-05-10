package gitlab

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// Fetcher collects all security-relevant data for a GitLab project.
//
// Kept separate from Client because:
// - Client: HTTP layer (how we connect)
// - Fetcher: business logic (what we collect and how we interpret it)
type Fetcher struct {
	client    *Client
	projectID string // "123" or "namespace/project-name" format
}

// NewFetcher creates a new Fetcher.
//
// projectID: GitLab project ID or "group/project" path.
//
//	Example: "42" or "mygroup/myproject"
//	Path values are URL-encoded: "mygroup%2Fmyproject"
func NewFetcher(client *Client, projectID string) *Fetcher {
	return &Fetcher{
		client:    client,
		projectID: url.PathEscape(projectID),
	}
}

// FetchAll collects all security-relevant project data and
// returns it in a single ProjectInfo struct.
func (f *Fetcher) FetchAll() (*ProjectInfo, error) {
	info := &ProjectInfo{}
	var err error

	fmt.Printf("[*] Fetching project info...\n")
	info.Project, err = f.FetchProject()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch project info: %w", err)
	}

	fmt.Printf("[*] Fetching CI/CD variables...\n")
	info.Variables, err = f.FetchVariables()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch variables: %w", err)
	}

	fmt.Printf("[*] Fetching environments...\n")
	info.Environments, err = f.FetchEnvironments()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch environments: %w", err)
	}

	fmt.Printf("[*] Fetching protected environments...\n")
	info.ProtectedEnvironments, err = f.FetchProtectedEnvironments()
	if err != nil {
		// Protected environment endpoint may not be available on all plans.
		// On error, leave empty and continue.
		fmt.Printf("[!] Failed to fetch protected environment info: %v\n", err)
	}

	fmt.Printf("[*] Fetching runners...\n")
	info.Runners, err = f.FetchRunners()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch runners: %w", err)
	}

	return info, nil
}

// FetchProject fetches basic project information.
func (f *Fetcher) FetchProject() (*Project, error) {
	endpoint := fmt.Sprintf("/api/v4/projects/%s", f.projectID)
	var project Project
	if err := f.client.get(endpoint, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// FetchVariables fetches all CI/CD variables for the project.
//
// Security concerns:
// - Protected=false secrets → visible to fork MRs as well
// - Masked=false secrets → may be exposed in logs
// - EnvironmentScope="*" critical secrets → injected into every environment
func (f *Fetcher) FetchVariables() ([]Variable, error) {
	endpoint := fmt.Sprintf("/api/v4/projects/%s/variables", f.projectID)

	rawItems, err := f.client.getWithPagination(endpoint)
	if err != nil {
		return nil, err
	}

	variables := make([]Variable, 0, len(rawItems))
	for _, raw := range rawItems {
		var v Variable
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		variables = append(variables, v)
	}

	return variables, nil
}

// FetchEnvironments fetches the project's deployment environments.
func (f *Fetcher) FetchEnvironments() ([]Environment, error) {
	endpoint := fmt.Sprintf("/api/v4/projects/%s/environments", f.projectID)

	rawItems, err := f.client.getWithPagination(endpoint)
	if err != nil {
		return nil, err
	}

	envs := make([]Environment, 0, len(rawItems))
	for _, raw := range rawItems {
		var e Environment
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}

	return envs, nil
}

// FetchProtectedEnvironments fetches which environments are protected.
//
// Protected environment = only authorized users can deploy.
// Unprotected production environment = any pipeline can deploy → risk.
func (f *Fetcher) FetchProtectedEnvironments() ([]ProtectedEnvironment, error) {
	endpoint := fmt.Sprintf("/api/v4/projects/%s/protected_environments", f.projectID)

	rawItems, err := f.client.getWithPagination(endpoint)
	if err != nil {
		return nil, err
	}

	protected := make([]ProtectedEnvironment, 0, len(rawItems))
	for _, raw := range rawItems {
		var pe ProtectedEnvironment
		if err := json.Unmarshal(raw, &pe); err != nil {
			return nil, err
		}
		protected = append(protected, pe)
	}

	return protected, nil
}

// FetchRunners fetches the runners assigned to the project.
//
// Shared runner risk:
// The same physical runner is used by multiple projects.
// Temp files, cache, and environment variables left on the runner
// can be read by jobs from other projects.
func (f *Fetcher) FetchRunners() ([]Runner, error) {
	endpoint := fmt.Sprintf("/api/v4/projects/%s/runners", f.projectID)

	rawItems, err := f.client.getWithPagination(endpoint)
	if err != nil {
		return nil, err
	}

	runners := make([]Runner, 0, len(rawItems))
	for _, raw := range rawItems {
		var r Runner
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		runners = append(runners, r)
	}

	return runners, nil
}

// UnprotectedSecrets returns variables where protected=false.
// These variables are injected into fork MRs as well — critical risk.
func UnprotectedSecrets(variables []Variable) []Variable {
	var risky []Variable
	for _, v := range variables {
		if !v.Protected {
			risky = append(risky, v)
		}
	}
	return risky
}

// UnmaskedSecrets returns variables where masked=false.
// The values of these variables may appear in job logs.
func UnmaskedSecrets(variables []Variable) []Variable {
	var risky []Variable
	for _, v := range variables {
		if !v.Masked {
			risky = append(risky, v)
		}
	}
	return risky
}

// IsEnvironmentProtected checks whether the given environment name
// is in the protected environment list.
func IsEnvironmentProtected(name string, protected []ProtectedEnvironment) bool {
	for _, pe := range protected {
		if pe.Name == name {
			return true
		}
	}
	return false
}

// HasSharedRunners checks whether the project uses any shared runners.
func HasSharedRunners(runners []Runner) bool {
	for _, r := range runners {
		if r.Shared && r.Active && !r.Paused {
			return true
		}
	}
	return false
}
