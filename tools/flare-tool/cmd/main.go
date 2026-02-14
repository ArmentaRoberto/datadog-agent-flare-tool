// Datadog Agent Flare Analysis Tool
//
// A standalone tool for analyzing Datadog Agent flare zip archives.
// Drop any flare zip file and get instant insights about agent health,
// configuration issues, connectivity problems, and more.
//
// Usage:
//
//	flare-tool <flare.zip> [flags]
//
// Flags:
//
//	--verbose, -v     Show all findings including INFO level
//	--json, -j        Output in JSON format
//	--list, -l        List all files in the archive
//	--help, -h        Show help
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/analyzer"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/report"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

const version = "1.0.0"

func main() {
	args := os.Args[1:]

	if len(args) == 0 || hasFlag(args, "-h", "--help") {
		printUsage()
		os.Exit(0)
	}

	if hasFlag(args, "--version") {
		fmt.Printf("flare-tool v%s\n", version)
		os.Exit(0)
	}

	verbose := hasFlag(args, "-v", "--verbose")
	jsonOutput := hasFlag(args, "-j", "--json")
	listFiles := hasFlag(args, "-l", "--list")

	// Find the zip file argument (first non-flag arg)
	var zipPath string
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			zipPath = arg
			break
		}
	}

	if zipPath == "" {
		fmt.Fprintln(os.Stderr, "Error: no flare zip file specified.")
		fmt.Fprintln(os.Stderr, "Usage: flare-tool <flare.zip> [flags]")
		os.Exit(1)
	}

	// Open the archive
	archive, err := extractor.Open(zipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer archive.Close()

	// List files mode
	if listFiles {
		printFileList(archive)
		os.Exit(0)
	}

	// Run analysis
	analysisReport := runAnalysis(archive)

	// Output
	if jsonOutput {
		report.GenerateJSON(os.Stdout, analysisReport)
	} else {
		report.Generate(os.Stdout, analysisReport, verbose)
	}

	// Exit code based on severity
	if analysisReport.Summary.CriticalCount > 0 {
		os.Exit(2)
	}
	if analysisReport.Summary.ErrorCount > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runAnalysis(archive *extractor.FlareArchive) *types.AnalysisReport {
	var allFindings []types.Finding
	analyzersRun := 0

	for _, a := range analyzer.Registry {
		findings := a.Analyze(archive)
		allFindings = append(allFindings, findings...)
		analyzersRun++
	}

	// Build flare info
	info := types.FlareInfo{
		Hostname:  archive.Hostname(),
		FileCount: archive.TotalFiles(),
		TotalSize: archive.TotalSize(),
	}

	// Try to extract version from status.log findings
	for _, f := range allFindings {
		if f.Title == "Agent version detected" && f.Category == types.CategoryGeneral {
			info.AgentVersion = strings.TrimPrefix(f.Description, "Agent version: ")
		}
		if f.Title == "Host platform information" && f.Category == types.CategoryMetadata {
			info.Platform = f.Description
		}
		if f.Title == "Installation method" && f.Category == types.CategoryMetadata {
			info.InstallMethod = f.Description
		}
	}

	// Extract log level from archive filename if possible
	logLevelRe := regexp.MustCompile(`-(debug|info|warn|error|trace)\.zip$`)
	// Not available here, but agent version was extracted from findings

	_ = logLevelRe // Used conceptually; the zip path isn't passed here

	// Build summary
	summary := types.ReportSummary{
		TotalFindings: len(allFindings),
		AnalyzersRun:  analyzersRun,
		FilesAnalyzed: archive.TotalFiles(),
	}

	for _, f := range allFindings {
		switch f.Severity {
		case types.SeverityCritical:
			summary.CriticalCount++
		case types.SeverityError:
			summary.ErrorCount++
		case types.SeverityWarning:
			summary.WarningCount++
		case types.SeverityInfo:
			summary.InfoCount++
		}
	}

	// Determine available sections
	sectionChecks := map[string]string{
		"logs/agent.log":           "Logs",
		"etc/datadog.yaml":         "Config",
		"status.log":               "Status",
		"health.yaml":              "Health",
		"diagnose.log":             "Diagnostics",
		"docker_ps.log":            "Docker",
		"k8s/kubelet_pods.yaml":    "Kubernetes",
		"expvar/forwarder":         "Expvars",
		"metadata/host.json":       "Metadata",
		"go-routine-dump.log":      "Goroutines",
		"tagger-list.json":         "Tagger",
		"secrets.log":              "Secrets",
		"ecs_metadata.json":        "ECS",
	}
	for file, section := range sectionChecks {
		if archive.HasFile(file) {
			summary.AvailableSections = append(summary.AvailableSections, section)
		}
	}

	return &types.AnalysisReport{
		FlareInfo: info,
		Findings:  allFindings,
		Summary:   summary,
	}
}

func printFileList(archive *extractor.FlareArchive) {
	fmt.Printf("Flare archive contents (hostname: %s):\n\n", archive.Hostname())
	files := archive.ListFiles()
	for _, f := range files {
		size := archive.FileSize(f)
		fmt.Printf("  %8d  %s\n", size, f)
	}
	fmt.Printf("\nTotal: %d files\n", len(files))
}

func printUsage() {
	fmt.Printf(`Datadog Agent Flare Analysis Tool v%s

A standalone tool for analyzing Datadog Agent flare zip archives.
Drop any flare zip file and get instant insights about agent health,
configuration issues, connectivity problems, and more.

USAGE:
    flare-tool <flare.zip> [flags]

FLAGS:
    -v, --verbose    Show all findings including INFO level
    -j, --json       Output in JSON format
    -l, --list       List all files in the archive
    -h, --help       Show this help message
    --version        Show version

EXAMPLES:
    flare-tool datadog-agent-2024-01-15.zip
    flare-tool datadog-agent-2024-01-15.zip --verbose
    flare-tool datadog-agent-2024-01-15.zip --json > report.json
    flare-tool datadog-agent-2024-01-15.zip --list

EXIT CODES:
    0    No critical or error findings
    1    Error-level findings detected
    2    Critical-level findings detected

ANALYZERS:
    This tool runs the following analyzers against the flare:
    - Configuration:   Inspects datadog.yaml, check configs, system-probe config
    - Status:          Parses agent status for version, forwarder issues, check errors
    - Health:          Checks component health from health.yaml
    - Logs:            Scans agent logs for errors, panics, OOM, known patterns
    - Connectivity:    Analyzes diagnose results, forwarder expvars, proxy settings
    - Checks:          Reviews loaded checks, config errors, autodiscovery issues
    - Resources:       Examines goroutine counts, memory usage, telemetry
    - Containers:      Inspects Docker, Kubernetes, ECS environments
    - Security:        Checks secrets config, file permissions, scrubbing status
    - Metadata:        Reviews host metadata, agent inventory, version history
    - Completeness:    Validates all expected flare files are present

`, version)
}

func hasFlag(args []string, flags ...string) bool {
	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag {
				return true
			}
		}
	}
	return false
}
