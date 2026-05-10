package parser

// Pipeline represents an entire .gitlab-ci.yml file.
//
// Every top-level key in YAML is either a reserved keyword (stages, variables...)
// or a job definition. The parser must distinguish between the two.
type Pipeline struct {
	Stages    []string          // Execution order: build → test → deploy
	Variables map[string]string // Global variables visible to all jobs
	Jobs      map[string]*Job   // Key: job name, Value: job details
}

// Job represents a single unit of work in the pipeline.
// From a security perspective, this is the most critical entity — who can access what?
type Job struct {
	// Name comes from the map key ("deploy-prod"), not from the YAML itself.
	// The parser fills this in.
	Name string

	Stage string   // Which stage it runs in: build, test, deploy...
	Image string   // Which Docker image it uses — is it trusted?
	Tags  []string // Which runner it runs on — shared or specific?

	Script       []string // Actual commands — what does this job do?
	BeforeScript []string `yaml:"before_script"`
	AfterScript  []string `yaml:"after_script"`

	// Variables injected into this job.
	// Critical: secrets like $K8S_TOKEN, $DB_PASSWORD appear here.
	Variables map[string]string

	// Which environment does it deploy to? "production" or "staging"?
	// Very important for blast radius.
	Environment *Environment

	// Determines when the job is triggered.
	// New syntax — works with if conditions.
	Rules []Rule

	// Old syntax — runs only on specific branches/tags.
	// GitLab still supports it; common in real projects.
	Only   *OnlyExcept
	Except *OnlyExcept

	// Which jobs must finish before this one starts?
	// Our edges in the graph come from here.
	Needs        []Need
	Dependencies []string

	// Files produced by the job — could they contain sensitive data?
	Artifacts *Artifacts

	// Should this job inherit global variables?
	// inherit: variables: false → job cannot see global secrets.
	Inherit *Inherit

	AllowFailure bool `yaml:"allow_failure"`
}

// Environment defines the environment a job deploys to.
// Is the "production" environment protected? We learn this from the GitLab API.
type Environment struct {
	Name string // "production", "staging", "review/feature-x"
	URL  string // Deployed URL
}

// Rule determines when a job runs under the new GitLab syntax.
//
// Example:
//
//	rules:
//	  - if: '$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME'  → run if MR exists
//	    when: always
//	  - if: '$CI_COMMIT_BRANCH == "main"'           → run on push to main
//	    when: on_success
//
// Security critical: does a fork MR also trigger this condition?
type Rule struct {
	If      string   // Evaluated condition — usually contains a CI variable
	When    string   // always | never | on_success | manual | delayed
	Changes []string // Run only when these files change
	Exists  []string // Run only if these files exist
}

// OnlyExcept defines branch/tag filters under the old GitLab syntax.
//
// Simple form:
//
//	only:
//	  - main
//	  - /^release-.*/
//
// Detailed form:
//
//	only:
//	  refs:
//	    - merge_requests
//	  variables:
//	    - $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^feature/
//
// We use RawItems to handle both; the parser distinguishes them.
type OnlyExcept struct {
	Refs      []string // Branch, tag, "merge_requests", etc.
	Variables []string // Conditional variable filters
	Changes   []string // File change filters
	RawItems  []string // For the simple string list form
}

// Need defines a DAG (Directed Acyclic Graph) dependency.
// A job cannot start until the other job finishes.
// Directly becomes an edge in our graph model.
//
// Example:
//
//	needs:
//	  - job: build-job
//	    artifacts: true
type Need struct {
	Job       string // Name of the required job
	Pipeline  string // Cross-pipeline dependency — another project?
	Artifacts bool   // Download that job's artifacts?
}

// Artifacts defines the files produced and stored by a job.
//
// Security note: files stored as artifacts can be read by other jobs.
// Risk of sensitive data leakage.
type Artifacts struct {
	Paths    []string          // Which files to store
	ExposeAs string            `yaml:"expose_as"` // Visible name in MR
	When     string            // always | on_success | on_failure
	ExpireIn string            `yaml:"expire_in"` // How long to keep them
	Reports  map[string]string // SAST, DAST, coverage reports
}

// Inherit controls whether global settings are passed down to this job.
//
// inherit: variables: false → job cannot see global CI/CD variables.
// Can be used as a security control.
//
// variables field can be bool or []string:
//
//	inherit:
//	  variables: false           → don't inherit any
//	  variables: [VAR1, VAR2]    → inherit only these
type Inherit struct {
	// interface{} because it can be bool or []string.
	// The parser resolves this.
	Variables interface{}
	Default   interface{}
}
