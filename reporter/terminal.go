package reporter

import (
	"fmt"
	"strings"

	"github.com/karakoc49/blastrad/graph"
)

// ANSI color codes — makes terminal output readable.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorWhite  = "\033[97m"
)

func severityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return colorRed + colorBold
	case "HIGH":
		return colorRed
	case "MEDIUM":
		return colorYellow
	default:
		return colorCyan
	}
}

// PrintFindings prints findings to the terminal in color.
// Filters duplicate paths and shows a summary.
func PrintFindings(findings []graph.Finding, projectName string) {
	findings = deduplicate(findings)

	printHeader(projectName, len(findings))

	if len(findings) == 0 {
		fmt.Printf("\n  %s✓ No critical security vulnerabilities found.%s\n\n", colorCyan, colorReset)
		return
	}

	for i, f := range findings {
		printFinding(i+1, f)
	}

	printSummary(findings)
}

func printHeader(projectName string, count int) {
	line := strings.Repeat("─", 70)
	fmt.Printf("\n%s%s%s\n", colorBold, line, colorReset)
	fmt.Printf("%s  blastrad — CI/CD Pipeline Attack Path Analyzer%s\n", colorBold, colorReset)
	fmt.Printf("%s%s%s\n", colorGray, line, colorReset)
	fmt.Printf("  Project : %s\n", projectName)
	fmt.Printf("  Findings: %s%d total%s\n", colorBold, count, colorReset)
	fmt.Printf("%s%s%s\n\n", colorGray, line, colorReset)
}

func printFinding(index int, f graph.Finding) {
	color := severityColor(f.Severity)
	line := strings.Repeat("─", 70)

	fmt.Printf("%s[%s] %s%s\n", color, f.Severity, f.Title, colorReset)
	fmt.Printf("%s%s%s\n", colorGray, line, colorReset)

	// Path visualization: A → B → C
	path := strings.Join(f.PathNames, " → ")
	fmt.Printf("  %sPath:%s         %s\n", colorBold, colorReset, path)
	fmt.Printf("  %sBlast Radius:%s %d critical resource(s)\n", colorBold, colorReset, f.BlastRadius)
	fmt.Printf("  %sDescription:%s\n", colorBold, colorReset)

	// Word-wrap long descriptions
	words := strings.Fields(f.Description)
	line2 := "    "
	for _, word := range words {
		if len(line2)+len(word)+1 > 72 {
			fmt.Println(line2)
			line2 = "    " + word
		} else {
			if line2 == "    " {
				line2 += word
			} else {
				line2 += " " + word
			}
		}
	}
	if line2 != "    " {
		fmt.Println(line2)
	}

	fmt.Println()
}

func printSummary(findings []graph.Finding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	line := strings.Repeat("─", 70)
	fmt.Printf("%s%s%s\n", colorGray, line, colorReset)
	fmt.Printf("  %sSummary:%s  ", colorBold, colorReset)

	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if n := counts[sev]; n > 0 {
			fmt.Printf("%s%s: %d%s  ", severityColor(sev), sev, n, colorReset)
		}
	}
	fmt.Printf("\n%s%s%s\n\n", colorGray, line, colorReset)
}

// deduplicate removes duplicate paths with the same start→end pair.
// The analyzer finds all paths; showing paths from the same source to the
// same target via different intermediate jobs creates noise.
func deduplicate(findings []graph.Finding) []graph.Finding {
	seen := make(map[string]bool)
	var result []graph.Finding

	for _, f := range findings {
		// Key: severity + first node + last node
		names := f.PathNames
		key := f.Severity + "|" + names[0] + "|" + names[len(names)-1]

		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}
