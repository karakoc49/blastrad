package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the root command to which all subcommands are attached.
// It runs when "blastrad" is typed.
var rootCmd = &cobra.Command{
	Use:   "blastrad",
	Short: "CI/CD pipeline attack path analyzer",
	Long: `blastrad analyzes GitLab CI/CD pipelines from a security perspective.

Using a graph-based approach, it finds attack paths from untrusted sources
(fork MRs, external triggers) to critical targets (production secrets,
unprotected environments) and calculates blast radius.`,
}

// Execute is cobra's entry point. Called by main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags go here.
}
