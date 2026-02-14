package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// ConfigAnalyzer inspects agent configuration for common issues.
type ConfigAnalyzer struct{}

func (a *ConfigAnalyzer) Name() string { return "Configuration Analyzer" }

func (a *ConfigAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeMainConfig(archive)...)
	findings = append(findings, a.analyzeRuntimeConfig(archive)...)
	findings = append(findings, a.analyzeCheckConfigs(archive)...)
	findings = append(findings, a.analyzeSystemProbeConfig(archive)...)

	return findings
}

func (a *ConfigAnalyzer) analyzeMainConfig(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("etc/datadog.yaml")
	if err != nil {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryConfig,
			Title:       "Missing main configuration file",
			Description: "etc/datadog.yaml not found in flare archive",
			Suggestion:  "This may indicate the agent was not properly configured or the flare was created in local mode.",
			SourceFile:  "etc/datadog.yaml",
		})
		return findings
	}

	configStr := string(data)

	// Check API key
	if apiKey, ok := yamlGetValue(data, "api_key"); ok {
		if apiKey == "" {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityCritical,
				Category:    types.CategoryConfig,
				Title:       "API key is empty",
				Description: "The api_key field is present but empty. The agent cannot communicate with Datadog.",
				Suggestion:  "Set a valid API key in datadog.yaml or via DD_API_KEY environment variable.",
				SourceFile:  "etc/datadog.yaml",
			})
		} else if strings.Contains(apiKey, "***") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryConfig,
				Title:       "API key is configured (scrubbed)",
				Description: "API key is present and has been properly scrubbed in the flare.",
				SourceFile:  "etc/datadog.yaml",
			})
		}
	} else if !yamlHasKey(data, "api_key") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryConfig,
			Title:       "API key not configured",
			Description: "No api_key field found in datadog.yaml.",
			Suggestion:  "Add api_key to datadog.yaml or set DD_API_KEY environment variable.",
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check site/dd_url
	if site, ok := yamlGetValue(data, "site"); ok {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Datadog site configured",
			Description: fmt.Sprintf("Agent is configured to send data to: %s", site),
			SourceFile:  "etc/datadog.yaml",
		})
	}
	if ddURL, ok := yamlGetValue(data, "dd_url"); ok {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryConfig,
			Title:       "Custom dd_url configured",
			Description: fmt.Sprintf("Agent uses custom endpoint: %s. This overrides the default site.", ddURL),
			Suggestion:  "Verify this is intentional. Consider using 'site' instead unless proxying.",
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check log level
	if logLevel, ok := yamlGetValue(data, "log_level"); ok {
		level := strings.ToLower(logLevel)
		if level == "debug" || level == "trace" {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryConfig,
				Title:       fmt.Sprintf("Log level set to %q", level),
				Description: "Elevated log levels generate high log volume and may impact performance.",
				Suggestion:  "Set log_level back to 'info' or 'warn' after troubleshooting.",
				SourceFile:  "etc/datadog.yaml",
			})
		}
	}

	// Check proxy
	if yamlHasKey(data, "proxy") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Proxy configured",
			Description: "Proxy settings detected in datadog.yaml.",
			Suggestion:  "Verify proxy allows connections to Datadog endpoints.",
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check hostname override
	if hostname, ok := yamlGetValue(data, "hostname"); ok && hostname != "" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Hostname override configured",
			Description: fmt.Sprintf("Agent hostname is manually set to: %s", hostname),
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check tags
	tagCount := yamlCountListItems(data, "tags")
	if tagCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Host tags configured",
			Description: fmt.Sprintf("%d host-level tags defined.", tagCount),
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check logs_enabled
	if logsEnabled, ok := yamlGetValue(data, "logs_enabled"); ok && logsEnabled == "true" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Log collection enabled",
			Description: "The agent is configured to collect logs.",
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Check APM
	if enabled, ok := yamlGetNestedValue(data, "apm_config", "enabled"); ok && enabled == "false" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "APM explicitly disabled",
			Description: "Trace collection (APM) has been explicitly disabled in config.",
			SourceFile:  "etc/datadog.yaml",
		})
	}

	// Detect potential credential leaks (despite scrubbing)
	credPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|token|secret|key)\s*[:=]\s*[^\s*]{8,}`),
	}
	for _, pat := range credPatterns {
		if matches := pat.FindAllString(configStr, 5); len(matches) > 0 {
			for _, m := range matches {
				if !strings.Contains(m, "***") && !strings.Contains(m, "REDACTED") {
					findings = append(findings, types.Finding{
						Severity:    types.SeverityWarning,
						Category:    types.CategorySecurity,
						Title:       "Possible unscrubbed credential in config",
						Description: fmt.Sprintf("Pattern matched near: %s...", truncate(m, 40)),
						Suggestion:  "Review the flare for sensitive data before sharing.",
						SourceFile:  "etc/datadog.yaml",
					})
				}
			}
		}
	}

	return findings
}

func (a *ConfigAnalyzer) analyzeRuntimeConfig(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	if !archive.HasFile("runtime_config_dump.yaml") {
		return findings
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryConfig,
		Title:       "Runtime config dump available",
		Description: "Full runtime configuration captured — shows actual resolved values at time of flare.",
		SourceFile:  "runtime_config_dump.yaml",
	})

	return findings
}

func (a *ConfigAnalyzer) analyzeCheckConfigs(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	confFiles := archive.ListDir("etc/confd/")
	if len(confFiles) == 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryChecks,
			Title:       "No check configurations found",
			Description: "The etc/confd/ directory is empty or missing.",
			Suggestion:  "Ensure checks are configured in conf.d/ or via autodiscovery.",
		})
		return findings
	}

	yamlCount := 0
	for _, f := range confFiles {
		if strings.HasSuffix(f, ".yaml") || strings.HasSuffix(f, ".yml") {
			yamlCount++
		}
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryChecks,
		Title:       "Check configurations detected",
		Description: fmt.Sprintf("Found %d configuration files in etc/confd/.", yamlCount),
	})

	return findings
}

func (a *ConfigAnalyzer) analyzeSystemProbeConfig(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	if !archive.HasFile("etc/system-probe.yaml") && !archive.HasFile("system_probe_runtime_config_dump.yaml") {
		return findings
	}

	data, err := archive.ReadFile("etc/system-probe.yaml")
	if err != nil {
		return findings
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryConfig,
		Title:       "System Probe configured",
		Description: "system-probe.yaml is present. Network Performance Monitoring or other eBPF features may be enabled.",
		SourceFile:  "etc/system-probe.yaml",
	})

	// Check NPM
	if enabled, ok := yamlGetNestedValue(data, "network_config", "enabled"); ok && enabled == "true" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Network Performance Monitoring enabled",
			Description: "NPM is active via system-probe.",
			SourceFile:  "etc/system-probe.yaml",
		})
	}

	// Check USM
	if enabled, ok := yamlGetNestedValue(data, "service_monitoring_config", "enabled"); ok && enabled == "true" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "Universal Service Monitoring enabled",
			Description: "USM is active via system-probe.",
			SourceFile:  "etc/system-probe.yaml",
		})
	}

	return findings
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
