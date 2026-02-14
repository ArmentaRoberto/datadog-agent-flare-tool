package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// StatusAnalyzer inspects the agent status output for issues.
type StatusAnalyzer struct{}

func (a *StatusAnalyzer) Name() string { return "Status Analyzer" }

func (a *StatusAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("status.log")
	if err != nil {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryHealth,
			Title:       "No status output available",
			Description: "status.log is missing. The agent may not have been running when the flare was created.",
			Suggestion:  "Re-create the flare while the agent is running (without --local flag).",
			SourceFile:  "status.log",
		})
		return findings
	}

	status := string(data)

	findings = append(findings, a.extractAgentVersion(status)...)
	findings = append(findings, a.checkForwarderStatus(status)...)
	findings = append(findings, a.checkCollectorStatus(status)...)
	findings = append(findings, a.checkEndpoints(status)...)
	findings = append(findings, a.checkClocks(status)...)
	findings = append(findings, a.checkHostname(status)...)

	return findings
}

func (a *StatusAnalyzer) extractAgentVersion(status string) []types.Finding {
	var findings []types.Finding

	versionRe := regexp.MustCompile(`Agent \(v([\d.]+(?:-[a-zA-Z0-9.]+)?)\)`)
	if m := versionRe.FindStringSubmatch(status); len(m) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryGeneral,
			Title:       "Agent version detected",
			Description: fmt.Sprintf("Agent version: %s", m[1]),
			SourceFile:  "status.log",
		})
	}

	return findings
}

func (a *StatusAnalyzer) checkForwarderStatus(status string) []types.Finding {
	var findings []types.Finding

	// Check for forwarder errors
	if strings.Contains(status, "Forwarder") {
		// Look for transaction drop indicators
		droppedRe := regexp.MustCompile(`Transactions dropped:\s*(\d+)`)
		if m := droppedRe.FindStringSubmatch(status); len(m) > 1 && m[1] != "0" {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategoryConnectivity,
				Title:       "Forwarder is dropping transactions",
				Description: fmt.Sprintf("%s transactions have been dropped. Data is being lost.", m[1]),
				Suggestion:  "Check network connectivity to Datadog. Review proxy settings and firewall rules.",
				SourceFile:  "status.log",
			})
		}

		// Check for retry queue
		retriedRe := regexp.MustCompile(`Transactions retried:\s*(\d+)`)
		if m := retriedRe.FindStringSubmatch(status); len(m) > 1 && m[1] != "0" {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryConnectivity,
				Title:       "Forwarder retrying transactions",
				Description: fmt.Sprintf("%s transactions have been retried, indicating intermittent connectivity issues.", m[1]),
				SourceFile:  "status.log",
			})
		}
	}

	// Check for API key validation
	if strings.Contains(status, "API key ending with") {
		apiKeyRe := regexp.MustCompile(`API key ending with (\w+)`)
		if m := apiKeyRe.FindStringSubmatch(status); len(m) > 1 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryConfig,
				Title:       "API key identified",
				Description: fmt.Sprintf("Agent using API key ending with: %s", m[1]),
				SourceFile:  "status.log",
			})
		}
	}
	if strings.Contains(status, "API Key invalid") || strings.Contains(status, "API key invalid") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryConnectivity,
			Title:       "Invalid API key",
			Description: "The configured API key is not recognized by Datadog.",
			Suggestion:  "Verify your API key at app.datadoghq.com > Organization Settings > API Keys.",
			SourceFile:  "status.log",
		})
	}

	return findings
}

func (a *StatusAnalyzer) checkCollectorStatus(status string) []types.Finding {
	var findings []types.Finding

	// Check for running checks
	runningRe := regexp.MustCompile(`Running Checks\s*\n\s*={3,}`)
	if runningRe.MatchString(status) {
		// Count check instances
		instanceRe := regexp.MustCompile(`Instance ID: (\S+) \[(\w+)\]`)
		instances := instanceRe.FindAllStringSubmatch(status, -1)

		if len(instances) == 0 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryChecks,
				Title:       "No running check instances found",
				Description: "The collector section shows no check instances are running.",
				Suggestion:  "Verify check configurations in conf.d/ or check autodiscovery settings.",
				SourceFile:  "status.log",
			})
		} else {
			okCount := 0
			errCount := 0
			for _, inst := range instances {
				if len(inst) > 2 && inst[2] == "OK" {
					okCount++
				} else {
					errCount++
				}
			}
			if errCount > 0 {
				findings = append(findings, types.Finding{
					Severity:    types.SeverityError,
					Category:    types.CategoryChecks,
					Title:       "Some check instances have errors",
					Description: fmt.Sprintf("%d check instance(s) OK, %d with errors.", okCount, errCount),
					Suggestion:  "Review config-check.log for check configuration details and error messages.",
					SourceFile:  "status.log",
				})
			} else if okCount > 0 {
				findings = append(findings, types.Finding{
					Severity:    types.SeverityInfo,
					Category:    types.CategoryChecks,
					Title:       "Checks running normally",
					Description: fmt.Sprintf("%d check instance(s) running without errors.", okCount),
					SourceFile:  "status.log",
				})
			}
		}
	}

	// Check for errors section
	errSectionRe := regexp.MustCompile(`(?s)Check Errors\s*\n\s*={3,}\n(.+?)(?:\n\s*\n|\n\s*={3,}|$)`)
	if m := errSectionRe.FindStringSubmatch(status); len(m) > 1 {
		errContent := strings.TrimSpace(m[1])
		if errContent != "" && !strings.Contains(errContent, "No check errors") {
			errLines := strings.Split(errContent, "\n")
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategoryChecks,
				Title:       "Check errors detected",
				Description: fmt.Sprintf("Found check errors (%d lines). First: %s", len(errLines), truncate(errLines[0], 100)),
				Suggestion:  "Review the full status.log for check error details.",
				SourceFile:  "status.log",
			})
		}
	}

	return findings
}

func (a *StatusAnalyzer) checkEndpoints(status string) []types.Finding {
	var findings []types.Finding

	endpointRe := regexp.MustCompile(`(?i)(https?://[^\s,]+datadoghq[^\s,]*)`)
	endpoints := endpointRe.FindAllString(status, -1)
	if len(endpoints) > 0 {
		seen := make(map[string]bool)
		var unique []string
		for _, ep := range endpoints {
			if !seen[ep] {
				seen[ep] = true
				unique = append(unique, ep)
			}
		}
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConnectivity,
			Title:       "Datadog endpoints detected",
			Description: fmt.Sprintf("Agent communicates with %d unique Datadog endpoint(s): %s", len(unique), strings.Join(unique, ", ")),
			SourceFile:  "status.log",
		})
	}

	return findings
}

func (a *StatusAnalyzer) checkClocks(status string) []types.Finding {
	var findings []types.Finding

	clockRe := regexp.MustCompile(`(?i)NTP offset:\s*([-\d.]+)\s*s`)
	if m := clockRe.FindStringSubmatch(status); len(m) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryHealth,
			Title:       "NTP clock offset",
			Description: fmt.Sprintf("NTP offset: %s seconds", m[1]),
			SourceFile:  "status.log",
		})
	}

	return findings
}

func (a *StatusAnalyzer) checkHostname(status string) []types.Finding {
	var findings []types.Finding

	hostnameRe := regexp.MustCompile(`Hostname:\s*(\S+)`)
	if m := hostnameRe.FindStringSubmatch(status); len(m) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryMetadata,
			Title:       "Hostname",
			Description: fmt.Sprintf("Resolved hostname: %s", m[1]),
			SourceFile:  "status.log",
		})

		// Hostname warnings
		hostname := m[1]
		if strings.Contains(hostname, "ip-") || strings.Contains(hostname, "i-") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryMetadata,
				Title:       "Cloud-provider default hostname",
				Description: fmt.Sprintf("Hostname %q looks like an auto-assigned cloud hostname.", hostname),
				Suggestion:  "Consider setting a stable hostname in datadog.yaml to avoid host churn on instance replacement.",
				SourceFile:  "status.log",
			})
		}
	}

	return findings
}
