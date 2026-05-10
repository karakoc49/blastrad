package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	gitlabcollector "github.com/karakoc49/blastrad/collector/gitlab"
	"github.com/karakoc49/blastrad/collector/parser"
	"github.com/karakoc49/blastrad/graph"
	"github.com/karakoc49/blastrad/reporter"
)

// scan command flag variables.
// cobra binds flags directly to these variables.
var (
	flagToken     string
	flagProjectID string
	flagGitLabURL string
	flagCIFile    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a pipeline and find attack paths",
	Long: `Analyzes the CI/CD pipeline of the specified GitLab project.

Parses the .gitlab-ci.yml file, fetches project data from the GitLab API,
and reports security-relevant attack paths.`,

	Example: `  # A project on GitLab.com
  blastrad scan --token glpat-xxx --project mygroup/myproject

  # Self-hosted GitLab
  blastrad scan --token glpat-xxx --project 42 --url https://gitlab.example.com

  # With a CI file at a different location
  blastrad scan --token glpat-xxx --project 42 --file ci/pipeline.yml`,

	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// StringVarP(target, long name, short name, default, description)
	scanCmd.Flags().StringVarP(&flagToken, "token", "t", "", "GitLab Personal Access Token (read_api scope) [required]")
	scanCmd.Flags().StringVarP(&flagProjectID, "project", "p", "", "Project ID or 'namespace/project' path [required]")
	scanCmd.Flags().StringVarP(&flagGitLabURL, "url", "u", "https://gitlab.com", "GitLab instance URL")
	scanCmd.Flags().StringVarP(&flagCIFile, "file", "f", ".gitlab-ci.yml", "CI/CD file path")

	scanCmd.MarkFlagRequired("token")
	scanCmd.MarkFlagRequired("project")
}

// runScan contains the main logic for the scan command.
// If it returns an error, cobra catches and displays it cleanly.
func runScan(cmd *cobra.Command, args []string) error {
	// 1. Parse the YAML file
	fmt.Printf("[*] Reading pipeline file: %s\n", flagCIFile)
	pipeline, err := parser.ParseFile(flagCIFile)
	if err != nil {
		return fmt.Errorf("pipeline parse error: %w", err)
	}
	fmt.Printf("    %d jobs found\n", len(pipeline.Jobs))

	// 2. Fetch project info from GitLab API
	fmt.Printf("[*] Connecting to GitLab API: %s\n", flagGitLabURL)
	client := gitlabcollector.NewClient(flagGitLabURL, flagToken)
	fetcher := gitlabcollector.NewFetcher(client, flagProjectID)

	info, err := fetcher.FetchAll()
	if err != nil {
		return fmt.Errorf("failed to fetch GitLab data: %w", err)
	}

	// 3. Build the graph
	fmt.Printf("[*] Building security graph...\n")
	g, err := graph.Build(pipeline, info)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}
	fmt.Printf("    %d nodes, %d edges\n", g.NodeCount(), g.EdgeCount())

	// 4. Analyze
	fmt.Printf("[*] Analyzing attack paths...\n\n")
	analyzer := graph.NewAnalyzer(g)
	findings := analyzer.Analyze()

	// 5. Report
	reporter.PrintFindings(findings, info.Project.PathWithNamespace)

	// Return exit code 1 if critical findings exist.
	// Useful for CI/CD integration: blastrad failure stops the pipeline.
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			os.Exit(1)
		}
	}

	return nil
}
