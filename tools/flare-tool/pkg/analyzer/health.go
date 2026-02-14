package analyzer

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// HealthAnalyzer inspects the health.yaml for component health issues.
type HealthAnalyzer struct{}

func (a *HealthAnalyzer) Name() string { return "Health Analyzer" }

func (a *HealthAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("health.yaml")
	if err != nil {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryHealth,
			Title:       "Health data unavailable",
			Description: "health.yaml not found. Agent health status is unknown.",
			SourceFile:  "health.yaml",
		})
		return findings
	}

	content := string(data)
	parsed := simpleYAMLMap(data)

	healthyCount := 0
	unhealthyCount := 0
	var unhealthyComponents []string

	for key, value := range parsed {
		valueLower := strings.ToLower(value)
		if strings.Contains(valueLower, "unhealthy") || strings.Contains(valueLower, "error") || strings.Contains(valueLower, "fail") {
			unhealthyCount++
			unhealthyComponents = append(unhealthyComponents, key)
		} else {
			healthyCount++
		}
	}

	// Also scan raw content for status patterns not caught by simple parsing
	if unhealthyCount == 0 && (strings.Contains(strings.ToLower(content), "unhealthy") || strings.Contains(strings.ToLower(content), "not healthy")) {
		unhealthyCount++
		unhealthyComponents = append(unhealthyComponents, "(detected in raw content)")
	}

	if unhealthyCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryHealth,
			Title:       "Unhealthy components detected",
			Description: fmt.Sprintf("%d component(s) unhealthy: %s", unhealthyCount, strings.Join(unhealthyComponents, ", ")),
			Suggestion:  "Check logs for the unhealthy components. Review health.yaml for details.",
			SourceFile:  "health.yaml",
		})
	}

	totalComponents := healthyCount + unhealthyCount
	if totalComponents > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryHealth,
			Title:       "Component health summary",
			Description: fmt.Sprintf("%d healthy, %d unhealthy component(s) out of %d total.", healthyCount, unhealthyCount, totalComponents),
			SourceFile:  "health.yaml",
		})
	}

	return findings
}
