package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// ResourceAnalyzer inspects agent resource usage (goroutines, memory, telemetry).
type ResourceAnalyzer struct{}

func (a *ResourceAnalyzer) Name() string { return "Resource Analyzer" }

func (a *ResourceAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeGoroutines(archive)...)
	findings = append(findings, a.analyzeExpvarAgent(archive)...)
	findings = append(findings, a.analyzeTelemetry(archive)...)

	return findings
}

func (a *ResourceAnalyzer) analyzeGoroutines(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("go-routine-dump.log")
	if err != nil {
		return findings
	}

	content := string(data)

	// Count goroutines
	goroutineRe := regexp.MustCompile(`goroutine \d+ \[`)
	goroutines := goroutineRe.FindAllString(content, -1)
	count := len(goroutines)

	sev := types.SeverityInfo
	if count > 1000 {
		sev = types.SeverityError
	} else if count > 500 {
		sev = types.SeverityWarning
	}

	findings = append(findings, types.Finding{
		Severity:    sev,
		Category:    types.CategoryResources,
		Title:       "Goroutine count",
		Description: fmt.Sprintf("Agent has %d active goroutines.", count),
		SourceFile:  "go-routine-dump.log",
	})

	if count > 1000 {
		findings[len(findings)-1].Suggestion = "High goroutine count may indicate a goroutine leak. Profile the agent with --profile flag."
	}

	// Check for blocked goroutines
	blockedRe := regexp.MustCompile(`goroutine \d+ \[(\w+), (\d+) minutes\]`)
	blockedMatches := blockedRe.FindAllStringSubmatch(content, -1)
	if len(blockedMatches) > 0 {
		var longBlocked []string
		for _, m := range blockedMatches {
			longBlocked = append(longBlocked, fmt.Sprintf("%s for %s min", m[1], m[2]))
		}
		if len(longBlocked) > 0 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryResources,
				Title:       "Long-blocked goroutines",
				Description: fmt.Sprintf("Found %d goroutines blocked for extended periods: %s", len(longBlocked), strings.Join(longBlocked[:min(5, len(longBlocked))], "; ")),
				Suggestion:  "Long-blocked goroutines may indicate deadlocks or resource contention.",
				SourceFile:  "go-routine-dump.log",
			})
		}
	}

	// Check for goroutine state distribution
	stateRe := regexp.MustCompile(`goroutine \d+ \[(\w[^,\]]*)\]`)
	stateCounts := make(map[string]int)
	for _, m := range stateRe.FindAllStringSubmatch(content, -1) {
		stateCounts[m[1]]++
	}

	if len(stateCounts) > 0 {
		var stateInfo []string
		for state, cnt := range stateCounts {
			stateInfo = append(stateInfo, fmt.Sprintf("%s: %d", state, cnt))
		}
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryResources,
			Title:       "Goroutine state distribution",
			Description: strings.Join(stateInfo, ", "),
			SourceFile:  "go-routine-dump.log",
		})
	}

	return findings
}

func (a *ResourceAnalyzer) analyzeExpvarAgent(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("expvar/agent")
	if err != nil {
		return findings
	}

	content := string(data)

	// Check memory stats
	memRe := regexp.MustCompile(`"Alloc"\s*:\s*(\d+)`)
	if m := memRe.FindStringSubmatch(content); len(m) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryResources,
			Title:       "Agent memory allocation (expvar)",
			Description: fmt.Sprintf("Current memory allocation: %s bytes", m[1]),
			SourceFile:  "expvar/agent",
		})
	}

	return findings
}

func (a *ResourceAnalyzer) analyzeTelemetry(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("telemetry.log")
	if err != nil {
		return findings
	}

	content := string(data)

	if len(content) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryResources,
			Title:       "Telemetry data available",
			Description: fmt.Sprintf("telemetry.log contains %d bytes of internal agent metrics.", len(content)),
			SourceFile:  "telemetry.log",
		})
	}

	return findings
}
