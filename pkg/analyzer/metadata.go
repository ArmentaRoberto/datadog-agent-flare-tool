package analyzer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// MetadataAnalyzer inspects host and agent metadata.
type MetadataAnalyzer struct{}

func (a *MetadataAnalyzer) Name() string { return "Metadata Analyzer" }

func (a *MetadataAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeHostMetadata(archive)...)
	findings = append(findings, a.analyzeInventoryAgent(archive)...)
	findings = append(findings, a.analyzeInstallInfo(archive)...)
	findings = append(findings, a.analyzeVersionHistory(archive)...)

	return findings
}

func (a *MetadataAnalyzer) analyzeHostMetadata(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("metadata/host.json")
	if err != nil {
		return findings
	}

	var hostMeta map[string]interface{}
	if err := json.Unmarshal(data, &hostMeta); err != nil {
		return findings
	}

	// Extract platform info
	if meta, ok := hostMeta["meta"].(map[string]interface{}); ok {
		var platformInfo []string
		if os, ok := meta["os"].(string); ok {
			platformInfo = append(platformInfo, "OS: "+os)
		}
		if platform, ok := meta["platform"].(string); ok {
			platformInfo = append(platformInfo, "Platform: "+platform)
		}
		if processor, ok := meta["processor"].(string); ok {
			platformInfo = append(platformInfo, "CPU: "+processor)
		}
		if len(platformInfo) > 0 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryMetadata,
				Title:       "Host platform information",
				Description: strings.Join(platformInfo, ", "),
				SourceFile:  "metadata/host.json",
			})
		}
	}

	// Check for cloud provider
	if gohai, ok := hostMeta["gohai"].(string); ok {
		if strings.Contains(gohai, "amazon") || strings.Contains(gohai, "aws") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryMetadata,
				Title:       "Cloud provider: AWS",
				Description: "Host is running on Amazon Web Services.",
				SourceFile:  "metadata/host.json",
			})
		} else if strings.Contains(gohai, "google") || strings.Contains(gohai, "gcp") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryMetadata,
				Title:       "Cloud provider: GCP",
				Description: "Host is running on Google Cloud Platform.",
				SourceFile:  "metadata/host.json",
			})
		} else if strings.Contains(gohai, "azure") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryMetadata,
				Title:       "Cloud provider: Azure",
				Description: "Host is running on Microsoft Azure.",
				SourceFile:  "metadata/host.json",
			})
		}
	}

	return findings
}

func (a *MetadataAnalyzer) analyzeInventoryAgent(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("metadata/inventory/agent.json")
	if err != nil {
		return findings
	}

	var inventory map[string]interface{}
	if err := json.Unmarshal(data, &inventory); err != nil {
		return findings
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryMetadata,
		Title:       "Agent inventory metadata available",
		Description: fmt.Sprintf("Inventory contains %d fields about the agent installation.", len(inventory)),
		SourceFile:  "metadata/inventory/agent.json",
	})

	return findings
}

func (a *MetadataAnalyzer) analyzeInstallInfo(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("install_info.log")
	if err != nil {
		return findings
	}

	content := string(data)

	if strings.Contains(content, "install_method") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryMetadata,
			Title:       "Installation method",
			Description: truncate(strings.TrimSpace(content), 200),
			SourceFile:  "install_info.log",
		})
	}

	return findings
}

func (a *MetadataAnalyzer) analyzeVersionHistory(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("version-history.json")
	if err != nil {
		return findings
	}

	var history map[string]interface{}
	if err := json.Unmarshal(data, &history); err != nil {
		return findings
	}

	if len(history) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryMetadata,
			Title:       "Version history",
			Description: fmt.Sprintf("Agent version history contains %d entries. The agent has been upgraded.", len(history)),
			SourceFile:  "version-history.json",
		})
	}

	return findings
}
