package gitlab

// Project represents project information returned from the GitLab API.
//
// API endpoint: GET /api/v4/projects/:id
type Project struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`

	// If true, pipelines can be triggered by fork MRs — untrusted code
	// can trigger a pipeline. Critical starting point for blast radius analysis.
	OnlyAllowMergeIfPipelineSucceeds bool `json:"only_allow_merge_if_pipeline_succeeds"`
}

// Variable represents a CI/CD variable.
//
// API endpoint: GET /api/v4/projects/:id/variables
type Variable struct {
	Key   string `json:"key"`   // Variable name: "K8S_TOKEN", "DB_PASSWORD"
	Value string `json:"value"` // Value (empty if masked)

	// Protected: true → only injected into protected branch/tag pipelines.
	// Protected: false → every pipeline including fork MRs can see this variable.
	// A secret with protected=false is a significant risk.
	Protected bool `json:"protected"`

	// Masked: true → value is hidden in job logs (shown as ***)
	// Masked: false → value can be written to logs.
	// Secrets with masked=false are exposed to log leakage.
	Masked bool `json:"masked"`

	// Raw: true → value is used without interpolation
	Raw bool `json:"raw"`

	// EnvironmentScope: which environments is this variable injected into?
	// "*" → all, "production" → only production jobs
	EnvironmentScope string `json:"environment_scope"`
}

// Environment represents a deployment environment.
//
// API endpoint: GET /api/v4/projects/:id/environments
type Environment struct {
	ID   int    `json:"id"`
	Name string `json:"name"` // "production", "staging", "review/feature-x"

	// State: available | stopped
	State string `json:"state"`

	// ExternalURL: the deployed address
	ExternalURL string `json:"external_url"`
}

// ProtectedEnvironment represents the protection settings of an environment.
// Only authorized users/roles can deploy.
//
// API endpoint: GET /api/v4/projects/:id/protected_environments
type ProtectedEnvironment struct {
	Name string `json:"name"`

	// DeployAccessLevels: who can deploy?
	// Empty or too broadly defined → security risk
	DeployAccessLevels []AccessLevel `json:"deploy_access_levels"`
}

// AccessLevel defines access permission for an environment.
type AccessLevel struct {
	// AccessLevel values:
	// 0  → No access
	// 30 → Developer
	// 40 → Maintainer
	// 60 → Admin
	AccessLevel int `json:"access_level"`
	UserID      int `json:"user_id"`  // Specific user?
	GroupID     int `json:"group_id"` // Specific group?
}

// Runner represents a GitLab runner.
//
// API endpoint: GET /api/v4/projects/:id/runners
type Runner struct {
	ID          int    `json:"id"`
	Description string `json:"description"`

	// Shared: true → this runner is also used by other projects.
	// A job running on a shared runner can access the runner's cache
	// and temp files — cross-project leakage risk.
	Shared bool `json:"is_shared"`

	// Active: is the runner operational?
	Active bool `json:"active"`

	// RunnerType: "instance_type" | "group_type" | "project_type"
	RunnerType string `json:"runner_type"`

	// Tags: matched against the "tags" field of jobs
	TagList []string `json:"tag_list"`

	// Paused: is the runner paused?
	Paused bool `json:"paused"`
}

// ProjectInfo holds all collected data about a project in one place.
// The Pipeline from the parser + this struct give the graph builder
// everything it needs.
type ProjectInfo struct {
	Project               *Project
	Variables             []Variable
	Environments          []Environment
	ProtectedEnvironments []ProtectedEnvironment
	Runners               []Runner
}
