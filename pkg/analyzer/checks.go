package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// ChecksAnalyzer inspects check configurations and config-check output.
type ChecksAnalyzer struct{}

func (a *ChecksAnalyzer) Name() string { return "Checks Analyzer" }

func (a *ChecksAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeConfigCheck(archive)...)
	findings = append(findings, a.analyzeExpvarCollector(archive)...)

	return findings
}

func (a *ChecksAnalyzer) analyzeConfigCheck(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("config-check.log")
	if err != nil {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryChecks,
			Title:       "config-check.log not available",
			Description: "Cannot analyze loaded check configurations.",
			SourceFile:  "config-check.log",
		})
		return findings
	}

	content := string(data)

	// Extract check names and their status
	checkHeaderRe := regexp.MustCompile(`=== (\S+) ===`)
	checks := checkHeaderRe.FindAllStringSubmatch(content, -1)

	if len(checks) > 0 {
		var checkNames []string
		for _, m := range checks {
			checkNames = append(checkNames, m[1])
		}
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryChecks,
			Title:       "Loaded checks",
			Description: fmt.Sprintf("%d check(s) loaded: %s", len(checkNames), strings.Join(checkNames, ", ")),
			SourceFile:  "config-check.log",
		})
	}

	// Check for configuration errors/warnings in the output
	if strings.Contains(content, "Configuration Errors") || strings.Contains(content, "Error:") {
		errRe := regexp.MustCompile(`(?i)Error:\s*(.+)`)
		errs := errRe.FindAllStringSubmatch(content, -1)
		for _, m := range errs {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategoryChecks,
				Title:       "Check configuration error",
				Description: truncate(strings.TrimSpace(m[1]), 200),
				Suggestion:  "Review the check configuration in conf.d/. Ensure YAML syntax is correct.",
				SourceFile:  "config-check.log",
			})
		}
	}

	// Check for autodiscovery-loaded checks
	if strings.Contains(content, "Auto-discovery") || strings.Contains(content, "autodiscovery") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryChecks,
			Title:       "Autodiscovery checks detected",
			Description: "Some checks are loaded via autodiscovery (annotations/labels).",
			SourceFile:  "config-check.log",
		})
	}

	// Detect unresolved template variables
	unresolvedRe := regexp.MustCompile(`%%[^%]+%%`)
	if unresolvedRe.MatchString(content) {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryChecks,
			Title:       "Unresolved autodiscovery template variables",
			Description: "Found %%...%% template variables that were not resolved.",
			Suggestion:  "Verify autodiscovery annotations/labels and ensure the integration container is detected.",
			SourceFile:  "config-check.log",
		})
	}

	return findings
}

func (a *ChecksAnalyzer) analyzeExpvarCollector(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("expvar/collector")
	if err != nil {
		return findings
	}

	content := string(data)

	// Look for check run errors
	errorRe := regexp.MustCompile(`"LastError"\s*:\s*"([^"]+)"`)
	errors := errorRe.FindAllStringSubmatch(content, -1)
	for _, m := range errors {
		if m[1] != "" {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategoryChecks,
				Title:       "Check runtime error (expvar)",
				Description: truncate(m[1], 200),
				SourceFile:  "expvar/collector",
			})
		}
	}

	// Look for high execution times
	execTimeRe := regexp.MustCompile(`"LastExecutionTime"\s*:\s*(\d+)`)
	for _, m := range execTimeRe.FindAllStringSubmatch(content, -1) {
		// Time is in nanoseconds or milliseconds depending on version
		if len(m) > 1 {
			timeStr := m[1]
			if len(timeStr) > 9 { // Likely nanoseconds > 1 second
				findings = append(findings, types.Finding{
					Severity:    types.SeverityWarning,
					Category:    types.CategoryChecks,
					Title:       "Slow check execution detected",
					Description: fmt.Sprintf("Check execution time: %s (high value detected in collector expvars).", timeStr),
					Suggestion:  "Long-running checks can delay other checks. Consider optimizing the check or increasing min_collection_interval.",
					SourceFile:  "expvar/collector",
				})
			}
		}
	}

	return findings
}
