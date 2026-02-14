package analyzer

import (
	"fmt"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// CompletenessAnalyzer checks whether all expected files are present.
type CompletenessAnalyzer struct{}

func (a *CompletenessAnalyzer) Name() string { return "Completeness Analyzer" }

// expectedFiles are files that should always be in a standard flare.
var expectedFiles = []string{
	"status.log",
	"config-check.log",
	"health.yaml",
	"runtime_config_dump.yaml",
	"envvars.log",
	"diagnose.log",
	"etc/datadog.yaml",
}

// optionalFiles are files that may or may not be present depending on config.
var optionalFiles = []struct {
	path    string
	feature string
}{
	{"logs/agent.log", "Core Agent logs"},
	{"logs/process-agent.log", "Process Agent logs"},
	{"logs/trace-agent.log", "Trace Agent (APM) logs"},
	{"logs/security-agent.log", "Security Agent"},
	{"logs/system-probe.log", "System Probe"},
	{"logs/jmxfetch.log", "JMX Fetch"},
	{"go-routine-dump.log", "Goroutine dump"},
	{"docker_ps.log", "Docker"},
	{"k8s/kubelet_pods.yaml", "Kubernetes"},
	{"ecs_metadata.json", "ECS"},
	{"tagger-list.json", "Tagger (non-local)"},
	{"workload-list.log", "Workload meta (non-local)"},
	{"secrets.log", "Secrets diagnostics"},
	{"permissions.log", "File permissions (Unix)"},
	{"metadata/host.json", "Host metadata"},
	{"metadata/inventory/agent.json", "Agent inventory"},
	{"metadata/inventory/host.json", "Host inventory"},
	{"telemetry.log", "Agent telemetry"},
	{"install_info.log", "Install information"},
	{"version-history.json", "Version history"},
	{"system_probe_runtime_config_dump.yaml", "System Probe config"},
	{"process_agent_runtime_config_dump.yaml", "Process Agent config"},
	{"expvar/forwarder", "Forwarder expvars"},
	{"expvar/agent", "Agent expvars"},
	{"expvar/collector", "Collector expvars"},
	{"expvar/dogstatsd", "DogStatsD expvars"},
	{"cluster-agent-status.log", "Cluster Agent"},
	{"non_scrubbed_files.json", "Scrub tracking"},
}

func (a *CompletenessAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	// Check required files
	var missing []string
	for _, f := range expectedFiles {
		if !archive.HasFile(f) {
			missing = append(missing, f)
		}
	}

	if len(missing) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryGeneral,
			Title:       "Missing expected flare files",
			Description: fmt.Sprintf("Missing %d expected files: %s", len(missing), strings.Join(missing, ", ")),
			Suggestion:  "The flare may have been created with --local flag or the agent was not running. Re-create with agent running.",
		})
	} else {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryGeneral,
			Title:       "All expected files present",
			Description: fmt.Sprintf("All %d expected flare files are present.", len(expectedFiles)),
		})
	}

	// Summarize optional features
	var enabled []string
	var notPresent []string
	for _, opt := range optionalFiles {
		if archive.HasFile(opt.path) {
			enabled = append(enabled, opt.feature)
		} else {
			notPresent = append(notPresent, opt.feature)
		}
	}

	if len(enabled) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryGeneral,
			Title:       "Available data sections",
			Description: fmt.Sprintf("Data available for: %s", strings.Join(enabled, ", ")),
		})
	}

	// Report the local flare marker
	if archive.HasFile("local") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryGeneral,
			Title:       "Local flare detected",
			Description: "This flare was created in local mode (--local). Runtime data from the agent process is not included.",
			Suggestion:  "For complete diagnostics, re-create the flare while the agent is running without --local.",
		})
	}

	// Report profiles
	profileFiles := archive.ListDir("profiles/")
	if len(profileFiles) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryGeneral,
			Title:       "Performance profiles included",
			Description: fmt.Sprintf("%d profile file(s) available for analysis (pprof format).", len(profileFiles)),
		})
	}

	return findings
}
