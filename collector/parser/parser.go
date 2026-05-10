package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// reservedKeys are the top-level keys in GitLab CI/CD that are not job definitions.
// Any key not in this list is treated as a job definition.
var reservedKeys = map[string]bool{
	"stages":        true,
	"variables":     true,
	"default":       true,
	"include":       true,
	"workflow":      true,
	"image":         true,
	"services":      true,
	"before_script": true,
	"after_script":  true,
	"cache":         true,
}

// ParseFile reads the .gitlab-ci.yml at the given path and
// converts it into a Pipeline struct.
//
// Splits into ParseFile → ParseBytes so tests can pass content directly.
func ParseFile(path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes takes raw YAML data and converts it into a Pipeline.
// Tests can pass strings directly without needing to open a file.
func ParseBytes(data []byte) (*Pipeline, error) {
	// Phase 1: Read everything as a raw map.
	// We use yaml.Node because we don't know each value's type yet.
	// Some are []string (stages), some are maps (variables), some are job objects.
	raw := make(map[string]yaml.Node)
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	pipeline := &Pipeline{
		Jobs: make(map[string]*Job),
	}

	// Phase 2: Inspect each key — reserved or not?
	for key, node := range raw {
		if reservedKeys[key] {
			if err := handleReservedKey(pipeline, key, &node); err != nil {
				return nil, fmt.Errorf("failed to parse '%s' field: %w", key, err)
			}
		} else {
			// This is a job definition.
			job, err := parseJob(key, &node)
			if err != nil {
				return nil, fmt.Errorf("failed to parse job '%s': %w", key, err)
			}
			pipeline.Jobs[key] = job
		}
	}

	return pipeline, nil
}

// handleReservedKey assigns known top-level keys to pipeline struct fields.
func handleReservedKey(p *Pipeline, key string, node *yaml.Node) error {
	switch key {
	case "stages":
		return node.Decode(&p.Stages)

	case "variables":
		return node.Decode(&p.Variables)

	default:
		return nil
	}
}

// parseJob takes a single job node and converts it into a Job struct.
//
// The name parameter comes from the YAML key: "deploy-prod", "build-app", etc.
// A job doesn't know its own name — it's stored as a map key and added here.
func parseJob(name string, node *yaml.Node) (*Job, error) {
	job := &Job{Name: name}

	// First decode the node as a raw map.
	// We do this because some fields (environment, only, needs) can appear
	// in different formats. Decoding raw first and handling each separately is safer.
	raw := make(map[string]yaml.Node)
	if err := node.Decode(&raw); err != nil {
		return nil, err
	}

	// Simple string fields — can be decoded directly.
	if n, ok := raw["stage"]; ok {
		n.Decode(&job.Stage)
	}
	if n, ok := raw["image"]; ok {
		// image can be either a string or a map:
		//   image: golang:1.21
		//   image:
		//     name: golang:1.21
		//     entrypoint: [""]
		n.Decode(&job.Image)
	}
	if n, ok := raw["tags"]; ok {
		n.Decode(&job.Tags)
	}
	if n, ok := raw["allow_failure"]; ok {
		n.Decode(&job.AllowFailure)
	}

	// Script fields — always []string
	if n, ok := raw["script"]; ok {
		n.Decode(&job.Script)
	}
	if n, ok := raw["before_script"]; ok {
		n.Decode(&job.BeforeScript)
	}
	if n, ok := raw["after_script"]; ok {
		n.Decode(&job.AfterScript)
	}

	// Variables — map[string]string
	if n, ok := raw["variables"]; ok {
		n.Decode(&job.Variables)
	}

	// Dependencies — []string
	if n, ok := raw["dependencies"]; ok {
		n.Decode(&job.Dependencies)
	}

	// Environment — string or object, needs special handling.
	if n, ok := raw["environment"]; ok {
		env, err := parseEnvironment(&n)
		if err != nil {
			return nil, fmt.Errorf("failed to parse environment: %w", err)
		}
		job.Environment = env
	}

	// Rules — new trigger syntax
	if n, ok := raw["rules"]; ok {
		n.Decode(&job.Rules)
	}

	// Only/Except — old trigger syntax
	if n, ok := raw["only"]; ok {
		only, err := parseOnlyExcept(&n)
		if err != nil {
			return nil, fmt.Errorf("failed to parse only: %w", err)
		}
		job.Only = only
	}
	if n, ok := raw["except"]; ok {
		except, err := parseOnlyExcept(&n)
		if err != nil {
			return nil, fmt.Errorf("failed to parse except: %w", err)
		}
		job.Except = except
	}

	// Needs — job dependencies
	if n, ok := raw["needs"]; ok {
		needs, err := parseNeeds(&n)
		if err != nil {
			return nil, fmt.Errorf("failed to parse needs: %w", err)
		}
		job.Needs = needs
	}

	// Artifacts
	if n, ok := raw["artifacts"]; ok {
		var artifacts Artifacts
		n.Decode(&artifacts)
		job.Artifacts = &artifacts
	}

	return job, nil
}

// parseEnvironment handles the environment field.
// It can appear in two formats:
//
// Simple:   environment: production
// Detailed: environment:
//
//	name: production
//	url: https://prod.example.com
func parseEnvironment(node *yaml.Node) (*Environment, error) {
	env := &Environment{}

	switch node.Kind {
	case yaml.ScalarNode:
		env.Name = node.Value

	case yaml.MappingNode:
		if err := node.Decode(env); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unexpected environment format")
	}

	return env, nil
}

// parseOnlyExcept handles the only/except field.
// It can appear in two formats:
//
// Simple list:
//
//	only:
//	  - main
//	  - develop
//
// Detailed object:
//
//	only:
//	  refs:
//	    - merge_requests
//	  variables:
//	    - $CI_PIPELINE_SOURCE == "schedule"
func parseOnlyExcept(node *yaml.Node) (*OnlyExcept, error) {
	oe := &OnlyExcept{}

	switch node.Kind {
	case yaml.SequenceNode:
		if err := node.Decode(&oe.RawItems); err != nil {
			return nil, err
		}
		oe.Refs = oe.RawItems

	case yaml.MappingNode:
		if err := node.Decode(oe); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unexpected only/except format")
	}

	return oe, nil
}

// parseNeeds handles the needs field.
// It can appear in two formats:
//
// Name only:
//
//	needs:
//	  - build-job
//
// Detailed:
//
//	needs:
//	  - job: build-job
//	    artifacts: true
func parseNeeds(node *yaml.Node) ([]Need, error) {
	var needs []Need

	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("needs must be a list")
	}

	for _, item := range node.Content {
		need := Need{Artifacts: true} // GitLab default: artifacts true

		switch item.Kind {
		case yaml.ScalarNode:
			// Job name only: "- build-job"
			need.Job = item.Value

		case yaml.MappingNode:
			// Detailed form: { job: build-job, artifacts: false }
			if err := item.Decode(&need); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unexpected needs item format")
		}

		needs = append(needs, need)
	}

	return needs, nil
}
