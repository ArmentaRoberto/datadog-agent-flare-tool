// Package report generates formatted analysis reports from flare findings.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// Generate runs all analysis and produces a formatted report written to w.
func Generate(w io.Writer, report *types.AnalysisReport, verbose bool) {
	printHeader(w, report)
	printSummary(w, report)
	printFindings(w, report, verbose)
	printFooter(w, report)
}

func printHeader(w io.Writer, report *types.AnalysisReport) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, strings.Repeat("=", 80))
	fmt.Fprintln(w, "           DATADOG AGENT FLARE ANALYSIS REPORT")
	fmt.Fprintln(w, strings.Repeat("=", 80))
	fmt.Fprintln(w, "")

	info := report.FlareInfo
	if info.Hostname != "" {
		fmt.Fprintf(w, "  Hostname:        %s\n", info.Hostname)
	}
	if info.AgentVersion != "" {
		fmt.Fprintf(w, "  Agent Version:   %s\n", info.AgentVersion)
	}
	if info.Platform != "" {
		fmt.Fprintf(w, "  Platform:        %s\n", info.Platform)
	}
	if info.InstallMethod != "" {
		fmt.Fprintf(w, "  Install Method:  %s\n", info.InstallMethod)
	}
	fmt.Fprintf(w, "  Files in Flare:  %d\n", info.FileCount)
	fmt.Fprintf(w, "  Total Size:      %s\n", humanSize(info.TotalSize))
	fmt.Fprintln(w, "")
}

func printSummary(w io.Writer, report *types.AnalysisReport) {
	s := report.Summary
	fmt.Fprintln(w, strings.Repeat("-", 80))
	fmt.Fprintln(w, "  SUMMARY")
	fmt.Fprintln(w, strings.Repeat("-", 80))
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  Analyzers Run:   %d\n", s.AnalyzersRun)
	fmt.Fprintf(w, "  Total Findings:  %d\n", s.TotalFindings)
	fmt.Fprintln(w, "")

	// Severity breakdown bar
	if s.CriticalCount > 0 {
		fmt.Fprintf(w, "    CRITICAL:  %d  %s\n", s.CriticalCount, bar(s.CriticalCount, s.TotalFindings))
	}
	if s.ErrorCount > 0 {
		fmt.Fprintf(w, "    ERROR:     %d  %s\n", s.ErrorCount, bar(s.ErrorCount, s.TotalFindings))
	}
	if s.WarningCount > 0 {
		fmt.Fprintf(w, "    WARNING:   %d  %s\n", s.WarningCount, bar(s.WarningCount, s.TotalFindings))
	}
	if s.InfoCount > 0 {
		fmt.Fprintf(w, "    INFO:      %d  %s\n", s.InfoCount, bar(s.InfoCount, s.TotalFindings))
	}
	fmt.Fprintln(w, "")

	if len(s.AvailableSections) > 0 {
		fmt.Fprintf(w, "  Available Sections: %s\n", strings.Join(s.AvailableSections, ", "))
		fmt.Fprintln(w, "")
	}

	if len(s.MissingFiles) > 0 {
		fmt.Fprintf(w, "  Missing Expected Files: %s\n", strings.Join(s.MissingFiles, ", "))
		fmt.Fprintln(w, "")
	}
}

func printFindings(w io.Writer, report *types.AnalysisReport, verbose bool) {
	// Group by severity, then by category
	grouped := groupFindings(report.Findings)

	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityError,
		types.SeverityWarning,
		types.SeverityInfo,
	}

	for _, sev := range severityOrder {
		categoryFindings, ok := grouped[sev]
		if !ok {
			continue
		}

		// Skip INFO in non-verbose mode
		if sev == types.SeverityInfo && !verbose {
			continue
		}

		fmt.Fprintln(w, strings.Repeat("-", 80))
		fmt.Fprintf(w, "  %s FINDINGS\n", sev)
		fmt.Fprintln(w, strings.Repeat("-", 80))
		fmt.Fprintln(w, "")

		// Sort categories
		var categories []types.Category
		for cat := range categoryFindings {
			categories = append(categories, cat)
		}
		sort.Slice(categories, func(i, j int) bool {
			return string(categories[i]) < string(categories[j])
		})

		for _, cat := range categories {
			findings := categoryFindings[cat]
			fmt.Fprintf(w, "  [%s]\n", cat)

			for _, f := range findings {
				fmt.Fprintf(w, "    * %s\n", f.Title)
				if f.Description != "" {
					// Indent description lines
					for _, line := range strings.Split(f.Description, "\n") {
						fmt.Fprintf(w, "      %s\n", line)
					}
				}
				if f.Suggestion != "" {
					fmt.Fprintf(w, "      -> %s\n", f.Suggestion)
				}
				if f.SourceFile != "" {
					fmt.Fprintf(w, "      (source: %s)\n", f.SourceFile)
				}
				fmt.Fprintln(w, "")
			}
		}
	}

	if !verbose {
		infoCount := 0
		if infoCat, ok := grouped[types.SeverityInfo]; ok {
			for _, findings := range infoCat {
				infoCount += len(findings)
			}
		}
		if infoCount > 0 {
			fmt.Fprintf(w, "  (%d INFO findings hidden. Use --verbose to show all.)\n\n", infoCount)
		}
	}
}

func printFooter(w io.Writer, report *types.AnalysisReport) {
	fmt.Fprintln(w, strings.Repeat("=", 80))

	s := report.Summary
	if s.CriticalCount > 0 {
		fmt.Fprintln(w, "  VERDICT: CRITICAL issues found that require immediate attention.")
	} else if s.ErrorCount > 0 {
		fmt.Fprintln(w, "  VERDICT: Errors detected. Review the findings above for remediation steps.")
	} else if s.WarningCount > 0 {
		fmt.Fprintln(w, "  VERDICT: Warnings present. The agent may be operational but review is recommended.")
	} else {
		fmt.Fprintln(w, "  VERDICT: No issues detected. Agent appears healthy.")
	}

	fmt.Fprintln(w, strings.Repeat("=", 80))
	fmt.Fprintln(w, "")
}

func groupFindings(findings []types.Finding) map[types.Severity]map[types.Category][]types.Finding {
	result := make(map[types.Severity]map[types.Category][]types.Finding)
	for _, f := range findings {
		if result[f.Severity] == nil {
			result[f.Severity] = make(map[types.Category][]types.Finding)
		}
		result[f.Severity][f.Category] = append(result[f.Severity][f.Category], f)
	}
	return result
}

func bar(count, total int) string {
	if total == 0 {
		return ""
	}
	width := 30
	filled := (count * width) / total
	if filled == 0 && count > 0 {
		filled = 1
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", width-filled) + "]"
}

func humanSize(bytes int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// GenerateJSON writes the report as JSON (for machine consumption).
func GenerateJSON(w io.Writer, report *types.AnalysisReport) error {
	fmt.Fprintln(w, "{")
	fmt.Fprintf(w, "  \"hostname\": %q,\n", report.FlareInfo.Hostname)
	fmt.Fprintf(w, "  \"agent_version\": %q,\n", report.FlareInfo.AgentVersion)
	fmt.Fprintf(w, "  \"total_findings\": %d,\n", report.Summary.TotalFindings)
	fmt.Fprintf(w, "  \"critical\": %d,\n", report.Summary.CriticalCount)
	fmt.Fprintf(w, "  \"errors\": %d,\n", report.Summary.ErrorCount)
	fmt.Fprintf(w, "  \"warnings\": %d,\n", report.Summary.WarningCount)
	fmt.Fprintf(w, "  \"info\": %d,\n", report.Summary.InfoCount)
	fmt.Fprintln(w, "  \"findings\": [")

	for i, f := range report.Findings {
		comma := ","
		if i == len(report.Findings)-1 {
			comma = ""
		}
		fmt.Fprintf(w, "    {\"severity\": %q, \"category\": %q, \"title\": %q, \"description\": %q, \"suggestion\": %q, \"source\": %q}%s\n",
			f.Severity, f.Category, f.Title, f.Description, f.Suggestion, f.SourceFile, comma)
	}

	fmt.Fprintln(w, "  ]")
	fmt.Fprintln(w, "}")
	return nil
}
