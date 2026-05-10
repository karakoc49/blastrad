package graph

import (
	"fmt"
	"strings"

	gitlabcollector "github.com/karakoc49/blastrad/collector/gitlab"
	"github.com/karakoc49/blastrad/collector/parser"
)

// Build takes a Pipeline from the parser and ProjectInfo from the GitLab API
// and converts them into a security graph.
//
// This function is the bridge that combines two data sources.
// After building the graph, the analyzer takes over.
func Build(pipeline *parser.Pipeline, info *gitlabcollector.ProjectInfo) (*Graph, error) {
	g := New()

	// Load protected environments into a set for fast lookup
	protectedEnvs := buildProtectedEnvSet(info.ProtectedEnvironments)

	// Load variables into a map for fast lookup
	variableMap := buildVariableMap(info.Variables)

	// STEP 1: Add trigger nodes.
	// These are the sources that initiate the pipeline.
	// Determining which are "untrusted" is critical.
	if err := addTriggerNodes(g, pipeline); err != nil {
		return nil, fmt.Errorf("failed to add trigger nodes: %w", err)
	}

	// STEP 2: Add job nodes
	for _, job := range pipeline.Jobs {
		jobNode := NewJobNode(job.Name, job.Stage)
		g.AddNode(jobNode)
	}

	// STEP 3: Add secret nodes (variables from the GitLab API)
	for _, v := range info.Variables {
		secretNode := NewSecretNode(v.Key, v.Protected, v.Masked)
		g.AddNode(secretNode)
	}

	// STEP 4: Add environment nodes
	for _, env := range info.Environments {
		isProtected := protectedEnvs[env.Name]
		envNode := NewEnvironmentNode(env.Name, isProtected)
		g.AddNode(envNode)
	}

	// STEP 5: Add runner nodes
	for _, runner := range info.Runners {
		runnerNode := NewRunnerNode(
			fmt.Sprintf("%d", runner.ID),
			runner.Description,
			runner.Shared,
		)
		g.AddNode(runnerNode)
	}

	// STEP 6: Build edges — answers "who is connected to whom?"
	if err := addEdges(g, pipeline, info, variableMap); err != nil {
		return nil, fmt.Errorf("failed to add edges: %w", err)
	}

	return g, nil
}

// addTriggerNodes adds the sources that can trigger the pipeline to the graph.
// Analyzes the rules/only fields of each job to create trigger nodes.
func addTriggerNodes(g *Graph, pipeline *parser.Pipeline) error {
	added := make(map[string]bool)

	addIfNew := func(name string, trusted bool) {
		if added[name] {
			return
		}
		g.AddNode(NewTriggerNode(name, trusted))
		added[name] = true
	}

	for _, job := range pipeline.Jobs {
		triggers := extractTriggers(job)
		for _, trigger := range triggers {
			trusted := isTrustedTrigger(trigger)
			addIfNew(trigger, trusted)
		}
	}

	// If no triggers were found, add a default push trigger
	if len(added) == 0 {
		addIfNew("push", true)
	}

	return nil
}

// extractTriggers extracts trigger conditions from a job's rules/only fields.
func extractTriggers(job *parser.Job) []string {
	var triggers []string

	// New syntax: rules
	for _, rule := range job.Rules {
		trigger := classifyRule(rule.If)
		if trigger != "" && !contains(triggers, trigger) {
			triggers = append(triggers, trigger)
		}
	}

	// Old syntax: only
	if job.Only != nil {
		for _, ref := range job.Only.Refs {
			trigger := classifyRef(ref)
			if trigger != "" && !contains(triggers, trigger) {
				triggers = append(triggers, trigger)
			}
		}
		for _, ref := range job.Only.RawItems {
			trigger := classifyRef(ref)
			if trigger != "" && !contains(triggers, trigger) {
				triggers = append(triggers, trigger)
			}
		}
	}

	// No rules found → runs on every push (GitLab default)
	if len(triggers) == 0 {
		triggers = append(triggers, "push")
	}

	return triggers
}

// classifyRule determines the trigger type from a rule's if condition.
// Recognizes and classifies GitLab CI variables.
func classifyRule(ifCondition string) string {
	if ifCondition == "" {
		return ""
	}

	lower := strings.ToLower(ifCondition)

	// Conditions that trigger for all MRs including forks → untrusted
	if strings.Contains(lower, "merge_request") {
		return "merge_request_event"
	}
	if strings.Contains(lower, "ci_merge_request_iid") {
		return "merge_request_event"
	}

	// Push to a specific branch → trusted
	if strings.Contains(lower, "ci_commit_branch") {
		return "push"
	}

	// Schedule → trusted
	if strings.Contains(lower, "pipeline_source") && strings.Contains(lower, "schedule") {
		return "schedule"
	}

	// API trigger
	if strings.Contains(lower, "pipeline_source") && strings.Contains(lower, "api") {
		return "api"
	}

	return "push" // Unknown conditions → assume push
}

// classifyRef converts a ref string from old syntax into a trigger type.
func classifyRef(ref string) string {
	switch strings.ToLower(ref) {
	case "merge_requests":
		return "merge_request_event"
	case "schedules":
		return "schedule"
	case "api":
		return "api"
	case "main", "master", "develop":
		return "push"
	default:
		return "push"
	}
}

// isTrustedTrigger determines whether a trigger is trusted.
// Untrusted trigger = a source that can be controlled externally.
func isTrustedTrigger(trigger string) bool {
	untrusted := map[string]bool{
		"merge_request_event": false, // anyone who opens a fork can trigger this
	}
	trusted, exists := untrusted[trigger]
	if !exists {
		return true // Unknown trigger → default to trusted
	}
	return trusted
}

// addEdges establishes relationships between nodes in the graph.
func addEdges(
	g *Graph,
	pipeline *parser.Pipeline,
	info *gitlabcollector.ProjectInfo,
	variableMap map[string]*gitlabcollector.Variable,
) error {
	runnerMap := buildRunnerTagMap(info.Runners)

	for _, job := range pipeline.Jobs {
		jobID := "job:" + job.Name

		// EDGE 1: Trigger → Job — which triggers can run this job?
		triggers := extractTriggers(job)
		for _, trigger := range triggers {
			triggerID := "trigger:" + trigger
			if _, exists := g.GetNode(triggerID); exists {
				if err := g.AddEdge(triggerID, jobID, EdgeTriggers); err != nil {
					return err
				}
			}
		}

		// EDGE 2: Job → Secret — which variables can this job access?
		// Job's own variables + global pipeline variables
		jobVarKeys := collectJobVariableKeys(job, pipeline)
		for _, key := range jobVarKeys {
			secretID := "secret:" + key
			if _, exists := g.GetNode(secretID); exists {
				if err := g.AddEdge(jobID, secretID, EdgeReadsSecret); err != nil {
					return err
				}
			}
		}

		// EDGE 3: Job → Environment — where does this job deploy to?
		if job.Environment != nil {
			envID := "env:" + job.Environment.Name
			if _, exists := g.GetNode(envID); exists {
				if err := g.AddEdge(jobID, envID, EdgeDeploysTo); err != nil {
					return err
				}
			}
		}

		// EDGE 4: Job → Runner — which runner does this job run on?
		// Job tags are matched against runner tag_list
		for _, tag := range job.Tags {
			if runners, ok := runnerMap[tag]; ok {
				for _, runner := range runners {
					runnerID := fmt.Sprintf("runner:%d", runner.ID)
					if _, exists := g.GetNode(runnerID); exists {
						if err := g.AddEdge(jobID, runnerID, EdgeRunsOn); err != nil {
							return err
						}
					}
				}
			}
		}

		// EDGE 5: Job → Job (needs/dependencies)
		for _, need := range job.Needs {
			neededJobID := "job:" + need.Job
			if _, exists := g.GetNode(neededJobID); exists {
				if err := g.AddEdge(jobID, neededJobID, EdgeDependsOn); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// collectJobVariableKeys collects all variable keys accessible by a job.
// Union of the job's own variables and global pipeline variables.
func collectJobVariableKeys(job *parser.Job, pipeline *parser.Pipeline) []string {
	seen := make(map[string]bool)
	var keys []string

	addKey := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}

	// Job-specific variables
	for k := range job.Variables {
		addKey(k)
	}

	// Global pipeline variables (visible to all jobs)
	for k := range pipeline.Variables {
		addKey(k)
	}

	return keys
}

func buildProtectedEnvSet(protected []gitlabcollector.ProtectedEnvironment) map[string]bool {
	set := make(map[string]bool)
	for _, pe := range protected {
		set[pe.Name] = true
	}
	return set
}

func buildVariableMap(variables []gitlabcollector.Variable) map[string]*gitlabcollector.Variable {
	m := make(map[string]*gitlabcollector.Variable)
	for i := range variables {
		m[variables[i].Key] = &variables[i]
	}
	return m
}

// buildRunnerTagMap builds a tag → runner list mapping.
// Answers: "On which runners can a job with this tag run?"
func buildRunnerTagMap(runners []gitlabcollector.Runner) map[string][]gitlabcollector.Runner {
	m := make(map[string][]gitlabcollector.Runner)
	for _, r := range runners {
		for _, tag := range r.TagList {
			m[tag] = append(m[tag], r)
		}
	}
	return m
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
