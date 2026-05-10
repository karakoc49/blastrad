# blastrad

**CI/CD Pipeline Attack Path Analyzer for GitLab**

<p align="center">
  <img width="380" alt="blastrad-gopher" src="https://i.imgur.com/HAeXwm4.png" />
</p>

blastrad models your GitLab CI/CD pipeline as a directed security graph and finds attack paths from untrusted sources to critical targets. It answers the question: *"If someone opens a fork merge request, what secrets and environments can they reach?"*

```
[CRITICAL] Privilege escalation: merge_request_event → deploy-production → K8S_TOKEN
──────────────────────────────────────────────────────────────────────────────────────
  Path:         merge_request_event → deploy-production → K8S_TOKEN
  Blast Radius: 3 critical resource(s)
  Description:  Untrusted source 'merge_request_event' can reach critical resource
                'K8S_TOKEN' (secret) in 2 step(s). An attacker can exploit this
                path to perform unauthorized actions.

[HIGH] Production job running on shared runner
──────────────────────────────────────────────────────────────────────────────────────
  Path:         deploy-production → shared-runner-01
  Blast Radius: 1 critical resource(s)
  Description:  Job 'deploy-production' deploys to production but uses shared
                runner 'shared-runner-01'. Jobs from other projects using this
                runner can access this job's temp files and cache.
```

---

## Why blastrad?

Most CI/CD security tools are rule-based: they flag a pattern and say *"this is bad"* — but they don't tell you *why it's bad*, *what an attacker can actually reach*, or *how many hops it takes*.

| Tool | What it does | What's missing |
|------|-------------|----------------|
| Checkov | YAML rule checks | No context, no relationship analysis |
| gitleaks | Secret scanning | Only secrets, no reachability analysis |
| zizmor | GitHub Actions linter | GitHub only, no GitLab support |
| Semgrep | Pattern matching | Not pipeline-specific |
| **blastrad** | **Graph-based attack path analysis** | — |

blastrad's differentiator: it shows *concretely* how many steps a fork MR attacker needs to reach `K8S_TOKEN`, which jobs they traverse, and how much damage they can do from there.

---

## How it works

Pipeline analysis happens in three phases:

**1. Data collection**

`.gitlab-ci.yml` is parsed to extract job definitions, trigger conditions, dependencies, and environment configuration. The GitLab API is then queried to fill in `protected`/`masked` state for variables, environment protection settings, and runner configuration.

**2. Graph modeling**

The collected data is converted into a directed graph:

```
Node types:  Trigger | Job | Secret | Environment | Runner
Edge types:  triggers | reads_secret | deploys_to | runs_on | depends_on

Example:
  [fork_mr] ──triggers──▶ [deploy-prod] ──reads_secret──▶ [K8S_TOKEN]
                                 │
                           ──deploys_to──▶ [production]
                                 │
                           ──runs_on──▶ [shared-runner-01]
```

**3. Analysis**

Two analyses run over the graph:

- **Privilege escalation path finding:** DFS starts from every untrusted trigger node. Any path that reaches a critical target (a `protected=false` secret or an unprotected production environment) is reported as a finding.
- **Blast radius calculation:** For each finding, the number of critical resources reachable from the target node is calculated.

---

## Installation

```bash
git clone https://github.com/karakoc49/blastrad
cd blastrad
go build -o blastrad .
```

Requires Go 1.22+.

---

## Usage

### Create a GitLab token

GitLab → Settings → Access Tokens → create a token with the `read_api` scope.

### Basic usage

```bash
blastrad scan --token glpat-xxxx --project mygroup/myproject
```

### Self-hosted GitLab

```bash
blastrad scan \
  --token glpat-xxxx \
  --project 42 \
  --url https://gitlab.example.com
```

### Non-default CI file path

```bash
blastrad scan \
  --token glpat-xxxx \
  --project mygroup/myproject \
  --file ci/production.yml
```

### All flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--token` | `-t` | — | GitLab Personal Access Token (`read_api` scope) **[required]** |
| `--project` | `-p` | — | Project ID or `namespace/project` path **[required]** |
| `--url` | `-u` | `https://gitlab.com` | GitLab instance URL |
| `--file` | `-f` | `.gitlab-ci.yml` | Path to the CI/CD file |

### CI/CD integration

blastrad exits with code `1` when CRITICAL or HIGH findings are present, making it easy to gate pipelines:

```yaml
# .gitlab-ci.yml
security-scan:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/karakoc49/blastrad@latest
    - blastrad scan --token $BLASTRAD_TOKEN --project $CI_PROJECT_PATH
  allow_failure: false  # Pipeline stops if critical findings are found
```

---

## Findings

### Privilege escalation path

A path from an untrusted source (anyone who can open a fork MR) to a critical target.

**Example scenario:**

```yaml
deploy-prod:
  environment: production
  variables:
    K8S_TOKEN: $KUBE_SECRET   # protected=false in GitLab
  rules:
    - if: '$CI_MERGE_REQUEST_IID'  # fork MRs can trigger this
```

blastrad detects that anyone who opens a fork can trigger `deploy-prod`, and `deploy-prod` can access `K8S_TOKEN`.

**Severity:** CRITICAL or HIGH depending on the variable's `protected`/`masked` state.

### Production job on shared runner

A job that deploys to a production environment runs on a runner shared with other projects.

**Risk:** Jobs from other projects running on the same shared runner can access temp files, cache, and in some cases environment variables left behind.

**Severity:** HIGH

---

## What to fix

| Finding | Fix |
|---------|-----|
| Unprotected secret reachable from fork MR | Set `protected=true` on the variable in GitLab → Settings → CI/CD → Variables, or add a rule to exclude MR pipelines from the deploying job |
| Production job on shared runner | Use a project-specific runner tagged for production jobs |
| Unprotected production environment | Enable environment protection in GitLab → Settings → CI/CD → Protected environments |

---

## Architecture

```
blastrad/
├── main.go
├── cmd/
│   ├── root.go          # cobra root command
│   └── scan.go          # "blastrad scan" subcommand and flag definitions
├── collector/
│   ├── parser/
│   │   ├── types.go     # Pipeline, Job, Rule, Environment structs
│   │   └── parser.go    # Two-phase YAML parsing logic
│   └── gitlab/
│       ├── types.go     # GitLab API response structs
│       ├── client.go    # HTTP layer with automatic pagination
│       └── fetcher.go   # Fetches variables, environments, runners
├── graph/
│   ├── node.go          # Node/Edge types, trust and criticality model
│   ├── graph.go         # Adjacency list graph implementation
│   ├── builder.go       # Converts parser + API data into a graph
│   └── analyzer.go      # DFS path finding, blast radius calculation
└── reporter/
    └── terminal.go      # Colored terminal output, deduplication
```

---

## Development

```bash
# Run all tests
go test ./...

# Run a specific package with verbose output
go test ./graph/... -v

# Build
go build -o blastrad .
```

### Adding a new rule

To add a new security rule, write a `find*` function in `graph/analyzer.go` and call it from `Analyze()`:

```go
func (a *Analyzer) Analyze() []Finding {
    var findings []Finding
    findings = append(findings, a.findPrivEscPaths()...)
    findings = append(findings, a.findSharedRunnerRisks()...)
    findings = append(findings, a.findMyNewRule()...)  // ← add here
    return findings
}
```

---

## Roadmap

- [ ] SARIF output (GitLab/GitHub Security Dashboard integration)
- [ ] GitHub Actions support
- [ ] JSON output format
- [ ] `--only-critical` flag for filtered output
- [ ] Cross-pipeline dependency analysis (`needs: pipeline:`)
- [ ] Follow `include:` directives to external CI files

---

## Required token scopes

| Scope | Reason |
|-------|--------|
| `read_api` | Read project variables, environments, and runners |

Both Personal Access Tokens and Project Access Tokens work.

---

## Limitations

- Reads the CI file from disk, not from the GitLab API (use `--file` for non-default paths)
- Does not follow `include:` directives to external files
- Cross-project pipeline dependencies (`needs: pipeline:`) are not traversed
- Dynamic child pipelines (`trigger:`) are not analyzed

---

## License

This project is distributed under the [AGPL-3.0](LICENSE) license.

For commercial use or private licensing: haluk.mkarakoc@gmail.com

---

*blastrad is an independent security tool written in Go and is not affiliated with GitLab Inc.*
