package parser

import (
	"testing"
)

// TestParseFile reads a real YAML file and checks that it is parsed correctly.
func TestParseFile(t *testing.T) {
	pipeline, err := ParseFile("../../testdata/sample.gitlab-ci.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Were stages read correctly?
	if len(pipeline.Stages) != 3 {
		t.Errorf("expected 3 stages, got %d", len(pipeline.Stages))
	}

	// Were global variables read?
	if pipeline.Variables["APP_ENV"] != "production" {
		t.Errorf("APP_ENV should be 'production', got '%s'", pipeline.Variables["APP_ENV"])
	}

	// Correct number of jobs?
	if len(pipeline.Jobs) != 4 {
		t.Errorf("expected 4 jobs, got %d: %v", len(pipeline.Jobs), jobNames(pipeline))
	}

	// Was deploy-production job parsed correctly?
	deploy, ok := pipeline.Jobs["deploy-production"]
	if !ok {
		t.Fatal("'deploy-production' job not found")
	}

	if deploy.Stage != "deploy" {
		t.Errorf("stage should be 'deploy', got '%s'", deploy.Stage)
	}

	if deploy.Environment == nil || deploy.Environment.Name != "production" {
		t.Error("environment should be 'production'")
	}

	// K8S_TOKEN should be visible in this job's variables
	if _, ok := deploy.Variables["K8S_TOKEN"]; !ok {
		t.Error("K8S_TOKEN should be in this job's variables")
	}

	// Were needs parsed correctly?
	if len(deploy.Needs) != 1 || deploy.Needs[0].Job != "run-tests" {
		t.Error("deploy-production should need the 'run-tests' job")
	}

	// Were rules parsed correctly?
	if len(deploy.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(deploy.Rules))
	}
}

// TestParseBytes tests parsing by passing YAML content directly as a string.
func TestParseBytes(t *testing.T) {
	yaml := `
stages:
  - build
  - deploy

variables:
  SECRET_TOKEN: $KUBE_TOKEN

build-job:
  stage: build
  image: golang:1.22
  tags:
    - shared
  script:
    - go build ./...
  rules:
    - if: '$CI_MERGE_REQUEST_IID'
      when: always

deploy-job:
  stage: deploy
  environment:
    name: production
  needs:
    - job: build-job
      artifacts: true
  script:
    - kubectl apply -f k8s/
  only:
    - main
`

	pipeline, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(pipeline.Jobs) != 2 {
		t.Errorf("expected 2 jobs, got %d", len(pipeline.Jobs))
	}

	// Environment as a simple string should also be parseable
	t.Run("EnvironmentAsString", func(t *testing.T) {
		yaml := `
build-job:
  stage: build
  script:
    - echo hi
  environment: staging
`
		p, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		job := p.Jobs["build-job"]
		if job.Environment == nil || job.Environment.Name != "staging" {
			t.Error("failed to parse environment as string")
		}
	})

	// needs can also be written as a plain string
	t.Run("NeedsAsString", func(t *testing.T) {
		yaml := `
deploy-job:
  stage: deploy
  needs:
    - build-job
  script:
    - echo deploy
`
		p, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		job := p.Jobs["deploy-job"]
		if len(job.Needs) != 1 || job.Needs[0].Job != "build-job" {
			t.Error("failed to parse needs as string")
		}
	})
}

// jobNames is a helper that returns job names for use in error messages.
func jobNames(p *Pipeline) []string {
	names := make([]string, 0, len(p.Jobs))
	for name := range p.Jobs {
		names = append(names, name)
	}
	return names
}
