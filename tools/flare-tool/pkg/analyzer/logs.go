package analyzer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// LogAnalyzer inspects agent log files for errors, panics, and patterns.
type LogAnalyzer struct{}

func (a *LogAnalyzer) Name() string { return "Log Analyzer" }

var logFiles = []string{
	"logs/agent.log",
	"logs/process-agent.log",
	"logs/trace-agent.log",
	"logs/security-agent.log",
	"logs/system-probe.log",
	"logs/jmxfetch.log",
}

func (a *LogAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	for _, logFile := range logFiles {
		if !archive.HasFile(logFile) {
			continue
		}
		findings = append(findings, a.analyzeLogFile(archive, logFile)...)
	}

	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryLogs,
			Title:       "No log files found",
			Description: "None of the expected agent log files were found in the flare.",
			Suggestion:  "Ensure the agent is running and log files are being generated.",
		})
	}

	return findings
}

func (a *LogAnalyzer) analyzeLogFile(archive *extractor.FlareArchive, logFile string) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile(logFile)
	if err != nil {
		return findings
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	componentName := logFileToComponent(logFile)

	// File size check
	size := archive.FileSize(logFile)
	if size > 50*1024*1024 { // > 50MB
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("Large log file: %s", componentName),
			Description: fmt.Sprintf("%s is %.1f MB. Excessive logging can impact performance.", logFile, float64(size)/(1024*1024)),
			Suggestion:  "Check log_level setting. Consider reducing to 'warn' or 'info'.",
			SourceFile:  logFile,
		})
	}

	// Count error/warn/panic/fatal occurrences
	errorCount := 0
	warnCount := 0
	panicCount := 0
	fatalCount := 0
	oomCount := 0

	errorRe := regexp.MustCompile(`(?i)\b(ERROR|ERRO)\b`)
	warnRe := regexp.MustCompile(`(?i)\b(WARN|WARNING)\b`)
	panicRe := regexp.MustCompile(`(?i)\bpanic\b`)
	fatalRe := regexp.MustCompile(`(?i)\bFATAL\b`)
	oomRe := regexp.MustCompile(`(?i)(out of memory|OOM|cannot allocate memory)`)

	// Track unique error messages (deduplicated)
	errorMessages := make(map[string]int)

	for _, line := range lines {
		if panicRe.MatchString(line) {
			panicCount++
		}
		if fatalRe.MatchString(line) {
			fatalCount++
		}
		if oomRe.MatchString(line) {
			oomCount++
		}
		if errorRe.MatchString(line) {
			errorCount++
			// Extract the error message portion (after the log level)
			msg := extractErrorMessage(line)
			if msg != "" {
				errorMessages[msg]++
			}
		}
		if warnRe.MatchString(line) {
			warnCount++
		}
	}

	// Report panics
	if panicCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("Panics detected in %s", componentName),
			Description: fmt.Sprintf("Found %d panic occurrence(s) in %s. The agent may have crashed.", panicCount, logFile),
			Suggestion:  "Review the full stack trace in the log file. This may require an agent upgrade or a bug report.",
			SourceFile:  logFile,
		})
	}

	// Report fatals
	if fatalCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("Fatal errors in %s", componentName),
			Description: fmt.Sprintf("Found %d FATAL log entries in %s.", fatalCount, logFile),
			Suggestion:  "Fatal errors usually prevent the agent from operating. Check for configuration or permission issues.",
			SourceFile:  logFile,
		})
	}

	// Report OOM
	if oomCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryResources,
			Title:       fmt.Sprintf("Out of memory errors in %s", componentName),
			Description: fmt.Sprintf("Found %d OOM-related messages. The agent or system is running out of memory.", oomCount),
			Suggestion:  "Increase memory limits or investigate memory-heavy checks/configurations.",
			SourceFile:  logFile,
		})
	}

	// Report top recurring errors
	if len(errorMessages) > 0 {
		type errEntry struct {
			msg   string
			count int
		}
		var sorted []errEntry
		for msg, count := range errorMessages {
			sorted = append(sorted, errEntry{msg, count})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })

		topN := 5
		if len(sorted) < topN {
			topN = len(sorted)
		}

		var topErrors []string
		for i := 0; i < topN; i++ {
			topErrors = append(topErrors, fmt.Sprintf("  (%dx) %s", sorted[i].count, truncate(sorted[i].msg, 120)))
		}

		sev := types.SeverityWarning
		if errorCount > 100 {
			sev = types.SeverityError
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("%s: %d errors, %d warnings", componentName, errorCount, warnCount),
			Description: fmt.Sprintf("Top recurring errors (%d unique):\n%s", len(errorMessages), strings.Join(topErrors, "\n")),
			SourceFile:  logFile,
		})
	} else {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("%s: %d lines, no errors", componentName, len(lines)),
			Description: fmt.Sprintf("Log file looks clean. %d warnings found.", warnCount),
			SourceFile:  logFile,
		})
	}

	// Check for specific known issues
	findings = append(findings, a.checkKnownPatterns(content, logFile, componentName)...)

	return findings
}

func (a *LogAnalyzer) checkKnownPatterns(content, logFile, component string) []types.Finding {
	var findings []types.Finding

	patterns := []struct {
		pattern    string
		severity   types.Severity
		title      string
		suggestion string
	}{
		{
			pattern:    "connection refused",
			severity:   types.SeverityError,
			title:      "Connection refused errors",
			suggestion: "Check that the target service is running and accessible. Verify firewall rules.",
		},
		{
			pattern:    "permission denied",
			severity:   types.SeverityError,
			title:      "Permission denied errors",
			suggestion: "Verify the dd-agent user has proper permissions. Check file ownership and SELinux policies.",
		},
		{
			pattern:    "certificate",
			severity:   types.SeverityWarning,
			title:      "TLS/certificate issues",
			suggestion: "Check TLS certificate validity, CA bundle configuration, and skip_ssl_validation settings.",
		},
		{
			pattern:    "timeout",
			severity:   types.SeverityWarning,
			title:      "Timeout errors",
			suggestion: "Network latency or service overload may cause timeouts. Review timeout configuration.",
		},
		{
			pattern:    "disk space",
			severity:   types.SeverityError,
			title:      "Disk space issues",
			suggestion: "Free up disk space. The agent may fail to write logs or buffer data.",
		},
		{
			pattern:    "too many open files",
			severity:   types.SeverityError,
			title:      "File descriptor exhaustion",
			suggestion: "Increase ulimit for the dd-agent user (nofile). Current limits may be too low.",
		},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			findings = append(findings, types.Finding{
				Severity:    p.severity,
				Category:    types.CategoryLogs,
				Title:       fmt.Sprintf("%s in %s (%d occurrences)", p.title, component, len(matches)),
				Description: fmt.Sprintf("Found %d occurrences of %q pattern.", len(matches), p.pattern),
				Suggestion:  p.suggestion,
				SourceFile:  logFile,
			})
		}
	}

	return findings
}

func extractErrorMessage(line string) string {
	// Try to extract the message after the log level
	re := regexp.MustCompile(`(?:ERROR|ERRO)\s*\|\s*(.{10,80})`)
	if m := re.FindStringSubmatch(line); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	// Fallback: take last part of line
	parts := strings.SplitN(line, "]", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(truncate(parts[1], 80))
	}
	return truncate(strings.TrimSpace(line), 80)
}

func logFileToComponent(path string) string {
	switch {
	case strings.Contains(path, "agent.log"):
		return "Core Agent"
	case strings.Contains(path, "process-agent"):
		return "Process Agent"
	case strings.Contains(path, "trace-agent"):
		return "Trace Agent"
	case strings.Contains(path, "security-agent"):
		return "Security Agent"
	case strings.Contains(path, "system-probe"):
		return "System Probe"
	case strings.Contains(path, "jmxfetch"):
		return "JMX Fetch"
	default:
		return path
	}
}
