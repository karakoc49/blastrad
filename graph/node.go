package graph

// NodeType specifies what kind of entity a node represents.
// We use NodeType to answer "is this node critical?" during analysis.
type NodeType string

const (
	NodeTypeTrigger     NodeType = "trigger"     // What initiates the pipeline
	NodeTypeJob         NodeType = "job"         // A CI job
	NodeTypeSecret      NodeType = "secret"      // CI/CD variable (e.g. K8S_TOKEN)
	NodeTypeEnvironment NodeType = "environment" // Deployment environment: production, staging, etc.
	NodeTypeRunner      NodeType = "runner"      // Runner that executes jobs
)

// TrustLevel indicates how much a node is trusted.
// The foundation of blast radius analysis:
// "Can an untrusted source reach a trusted critical target?"
type TrustLevel string

const (
	// Untrusted: can be controlled externally.
	// Anyone (including fork opener) can trigger this node.
	TrustUntrusted TrustLevel = "untrusted"

	// Trusted: only authorized users can trigger.
	// Protected branch, approved MR, specific runner, etc.
	TrustTrusted TrustLevel = "trusted"
)

// CriticalityLevel indicates the criticality of a node.
// "How much damage would compromising this node cause?"
type CriticalityLevel string

const (
	CriticalityLow      CriticalityLevel = "low"
	CriticalityMedium   CriticalityLevel = "medium"
	CriticalityHigh     CriticalityLevel = "high"
	CriticalityCritical CriticalityLevel = "critical"
)

// Node represents an entity in the graph.
// Each node has an ID, a type, and metadata.
type Node struct {
	// ID: used to identify this node in the graph.
	// Format: "<type>:<name>" → "job:deploy-prod", "secret:K8S_TOKEN"
	// Prevents collisions between nodes of different types with the same name.
	ID string

	// Type: what kind of entity is this node?
	Type NodeType

	// Name: human-readable name used in reports.
	Name string

	// Trust: how trusted is this node?
	// The analyzer looks for paths from Untrusted to trusted critical nodes.
	Trust TrustLevel

	// Criticality: how bad is it if this node is compromised?
	Criticality CriticalityLevel

	// Metadata: additional node-specific information.
	// For job: stage, image, tags
	// For secret: is it protected? masked?
	// For environment: is it protected?
	Metadata map[string]string
}

// EdgeType specifies the type of relationship between two nodes.
type EdgeType string

const (
	// EdgeTriggers: node A can trigger job B.
	// Example: fork_mr → deploy-prod
	EdgeTriggers EdgeType = "triggers"

	// EdgeReadsSecret: job A can read secret B.
	// Example: deploy-prod → K8S_TOKEN
	EdgeReadsSecret EdgeType = "reads_secret"

	// EdgeDeploysTo: job A deploys to environment B.
	// Example: deploy-prod → production
	EdgeDeploysTo EdgeType = "deploys_to"

	// EdgeRunsOn: job A runs on runner B.
	// Example: build-job → shared-runner-01
	EdgeRunsOn EdgeType = "runs_on"

	// EdgeDependsOn: job A requires job B to finish before starting.
	// Example: deploy-prod → run-tests (needs)
	EdgeDependsOn EdgeType = "depends_on"
)

// Edge represents a directed relationship between two nodes.
type Edge struct {
	From string   // Source node ID
	To   string   // Destination node ID
	Type EdgeType // Type of relationship
}

// NewTriggerNode creates a node for a pipeline trigger.
// trigger: "fork_mr", "push_to_main", "schedule", "api", etc.
func NewTriggerNode(trigger string, trusted bool) *Node {
	trust := TrustUntrusted
	if trusted {
		trust = TrustTrusted
	}
	return &Node{
		ID:          "trigger:" + trigger,
		Type:        NodeTypeTrigger,
		Name:        trigger,
		Trust:       trust,
		Criticality: CriticalityLow, // The trigger itself is not critical; what it reaches is.
		Metadata:    make(map[string]string),
	}
}

// NewJobNode creates a node for a CI job.
func NewJobNode(name, stage string) *Node {
	return &Node{
		ID:          "job:" + name,
		Type:        NodeTypeJob,
		Name:        name,
		Trust:       TrustUntrusted, // Default: untrusted. Builder can update later.
		Criticality: CriticalityLow,
		Metadata: map[string]string{
			"stage": stage,
		},
	}
}

// NewSecretNode creates a node for a CI/CD variable.
// The protected and masked flags determine criticality.
func NewSecretNode(key string, protected, masked bool) *Node {
	// Calculate criticality.
	//
	// protected=false → every pipeline including fork MRs CAN READ this secret.
	//                   Masking does not save this — the secret is accessible.
	//                   → CRITICAL
	//
	// protected=true, masked=false → fork MRs cannot see it, but the value
	//                                can be written clearly to job logs.
	//                                → MEDIUM
	//
	// protected=true, masked=true  → neither visible to forks nor written to logs.
	//                                → LOW
	var criticality CriticalityLevel
	if !protected {
		criticality = CriticalityCritical
	} else if !masked {
		criticality = CriticalityMedium
	} else {
		criticality = CriticalityLow
	}

	return &Node{
		ID:          "secret:" + key,
		Type:        NodeTypeSecret,
		Name:        key,
		Trust:       TrustTrusted, // The secret itself is trusted; the job reading it may not be.
		Criticality: criticality,
		Metadata: map[string]string{
			"protected": boolToStr(protected),
			"masked":    boolToStr(masked),
		},
	}
}

// NewEnvironmentNode creates a node for a deployment environment.
func NewEnvironmentNode(name string, isProtected bool) *Node {
	criticality := CriticalityHigh
	if name == "production" || name == "prod" {
		criticality = CriticalityCritical
	}
	if isProtected {
		criticality = CriticalityMedium
	}

	return &Node{
		ID:          "env:" + name,
		Type:        NodeTypeEnvironment,
		Name:        name,
		Trust:       TrustTrusted,
		Criticality: criticality,
		Metadata: map[string]string{
			"protected": boolToStr(isProtected),
		},
	}
}

// NewRunnerNode creates a node for a runner.
func NewRunnerNode(id, description string, shared bool) *Node {
	criticality := CriticalityLow
	if shared {
		// Shared runner: other projects' jobs also run here
		criticality = CriticalityMedium
	}
	return &Node{
		ID:          "runner:" + id,
		Type:        NodeTypeRunner,
		Name:        description,
		Trust:       TrustTrusted,
		Criticality: criticality,
		Metadata: map[string]string{
			"shared": boolToStr(shared),
		},
	}
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
