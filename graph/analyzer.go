package graph

import "fmt"

// Finding represents a single security issue found during analysis.
// The reporting layer receives these structs and presents them to the user.
type Finding struct {
	// Severity: how serious is this finding
	Severity string // "CRITICAL", "HIGH", "MEDIUM", "LOW"

	// Title: short description
	Title string

	// Path: attack path — ordered list of node IDs
	// ["trigger:merge_request_event", "job:deploy-prod", "secret:K8S_TOKEN"]
	Path []string

	// PathNames: same path with human-readable names
	// ["merge_request_event", "deploy-prod", "K8S_TOKEN"]
	PathNames []string

	// BlastRadius: how much damage can be done from the last node in this path
	BlastRadius int

	// Description: explains what happened and why it is dangerous
	Description string
}

// Analyzer analyzes the graph and produces security findings.
type Analyzer struct {
	graph *Graph
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer(g *Graph) *Analyzer {
	return &Analyzer{graph: g}
}

// Analyze runs all analysis steps and returns findings.
func (a *Analyzer) Analyze() []Finding {
	var findings []Finding

	// 1. Untrusted → critical node path analysis
	pathFindings := a.findPrivEscPaths()
	findings = append(findings, pathFindings...)

	// 2. Production job running on shared runner
	sharedRunnerFindings := a.findSharedRunnerRisks()
	findings = append(findings, sharedRunnerFindings...)

	// Sort by severity: CRITICAL → HIGH → MEDIUM → LOW
	sortBySeverity(findings)

	return findings
}

// findPrivEscPaths finds all paths from untrusted triggers to critical nodes.
//
// Algorithm: start a DFS from each untrusted trigger node.
// If we reach a critical node (protected=false secret, unprotected env) → finding.
func (a *Analyzer) findPrivEscPaths() []Finding {
	var findings []Finding

	for _, node := range a.graph.AllNodes() {
		if node.Type != NodeTypeTrigger || node.Trust != TrustUntrusted {
			continue
		}

		paths := a.dfs(node.ID, nil, make(map[string]bool))
		for _, path := range paths {
			lastNodeID := path[len(path)-1]
			lastNode, ok := a.graph.GetNode(lastNodeID)
			if !ok {
				continue
			}

			if !isCriticalTarget(lastNode) {
				continue
			}

			finding := a.buildFinding(path, lastNode)
			findings = append(findings, finding)
		}
	}

	return findings
}

// dfs finds all paths reachable from a given node.
// Uses a visited map to prevent cycles.
//
// currentPath: IDs of nodes visited so far
// visited: nodes visited to prevent cycles
//
// Returns: [][]string where each element is a complete path
func (a *Analyzer) dfs(
	nodeID string,
	currentPath []string,
	visited map[string]bool,
) [][]string {
	if visited[nodeID] {
		return nil
	}

	currentPath = append(currentPath, nodeID)
	visited[nodeID] = true

	neighbors := a.graph.Neighbors(nodeID)

	if len(neighbors) == 0 {
		// Leaf node — this path ends here.
		// Copy the path to avoid slice sharing issues.
		result := make([]string, len(currentPath))
		copy(result, currentPath)
		visited[nodeID] = false // Backtrack
		return [][]string{result}
	}

	var allPaths [][]string
	for _, neighbor := range neighbors {
		// Copy visited for each branch so branches don't affect each other.
		newVisited := copyMap(visited)
		subPaths := a.dfs(neighbor.ID, currentPath, newVisited)
		allPaths = append(allPaths, subPaths...)
	}

	visited[nodeID] = false // Backtrack
	return allPaths
}

// findSharedRunnerRisks detects production jobs running on shared runners.
//
// Risk: temp files, cache, and environment variables left on a shared runner
// can be read by jobs from other projects.
func (a *Analyzer) findSharedRunnerRisks() []Finding {
	var findings []Finding

	for _, node := range a.graph.AllNodes() {
		if node.Type != NodeTypeJob {
			continue
		}

		// Does this job deploy to production?
		deploysToProduction := false
		for _, edge := range a.graph.EdgesFrom(node.ID) {
			if edge.Type != EdgeDeploysTo {
				continue
			}
			envNode, ok := a.graph.GetNode(edge.To)
			if ok && (envNode.Name == "production" || envNode.Name == "prod") {
				deploysToProduction = true
				break
			}
		}

		if !deploysToProduction {
			continue
		}

		// Is this job running on a shared runner?
		for _, edge := range a.graph.EdgesFrom(node.ID) {
			if edge.Type != EdgeRunsOn {
				continue
			}
			runnerNode, ok := a.graph.GetNode(edge.To)
			if !ok {
				continue
			}
			if runnerNode.Metadata["shared"] == "true" {
				findings = append(findings, Finding{
					Severity:    "HIGH",
					Title:       "Production job running on shared runner",
					Path:        []string{node.ID, edge.To},
					PathNames:   []string{node.Name, runnerNode.Name},
					BlastRadius: 1,
					Description: fmt.Sprintf(
						"Job '%s' deploys to production but uses shared runner '%s'. "+
							"Jobs from other projects using this runner can access "+
							"this job's temp files and cache.",
						node.Name, runnerNode.Name,
					),
				})
			}
		}
	}

	return findings
}

// buildFinding converts a found path into a Finding struct.
func (a *Analyzer) buildFinding(path []string, targetNode *Node) Finding {
	names := make([]string, len(path))
	for i, id := range path {
		if node, ok := a.graph.GetNode(id); ok {
			names[i] = node.Name
		} else {
			names[i] = id
		}
	}

	severity := criticalityToSeverity(targetNode.Criticality)
	hopCount := len(path) - 1

	return Finding{
		Severity:    severity,
		Title:       fmt.Sprintf("Privilege escalation: %s → %s", names[0], names[len(names)-1]),
		Path:        path,
		PathNames:   names,
		BlastRadius: calculateBlastRadius(a.graph, targetNode.ID),
		Description: fmt.Sprintf(
			"Untrusted source '%s' can reach critical resource '%s' (%s) in %d step(s). "+
				"An attacker can exploit this path to perform unauthorized actions.",
			names[0], names[len(names)-1], targetNode.Type, hopCount,
		),
	}
}

// isCriticalTarget determines whether a node is considered a critical attack target.
func isCriticalTarget(node *Node) bool {
	switch node.Type {
	case NodeTypeSecret:
		return node.Metadata["protected"] == "false"
	case NodeTypeEnvironment:
		return node.Metadata["protected"] == "false" &&
			(node.Name == "production" || node.Name == "prod")
	default:
		return false
	}
}

// calculateBlastRadius counts the number of critical nodes reachable from a given node.
// "If this node is compromised, how many critical things can be accessed?"
func calculateBlastRadius(g *Graph, startNodeID string) int {
	visited := make(map[string]bool)
	criticalCount := 0

	var traverse func(id string)
	traverse = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true

		node, ok := g.GetNode(id)
		if !ok {
			return
		}

		if node.Criticality == CriticalityHigh || node.Criticality == CriticalityCritical {
			criticalCount++
		}

		for _, neighbor := range g.Neighbors(id) {
			traverse(neighbor.ID)
		}
	}

	traverse(startNodeID)
	return criticalCount
}

func criticalityToSeverity(c CriticalityLevel) string {
	switch c {
	case CriticalityCritical:
		return "CRITICAL"
	case CriticalityHigh:
		return "HIGH"
	case CriticalityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func sortBySeverity(findings []Finding) {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if order[findings[i].Severity] > order[findings[j].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

func copyMap(m map[string]bool) map[string]bool {
	result := make(map[string]bool, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

var _ = fmt.Sprintf
