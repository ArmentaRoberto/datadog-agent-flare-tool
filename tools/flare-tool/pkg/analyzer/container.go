package analyzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// ContainerAnalyzer inspects container and Kubernetes-related data.
type ContainerAnalyzer struct{}

func (a *ContainerAnalyzer) Name() string { return "Container & Kubernetes Analyzer" }

func (a *ContainerAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeDocker(archive)...)
	findings = append(findings, a.analyzeKubernetes(archive)...)
	findings = append(findings, a.analyzeECS(archive)...)
	findings = append(findings, a.analyzeTaggerList(archive)...)

	return findings
}

func (a *ContainerAnalyzer) analyzeDocker(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("docker_ps.log")
	if err != nil {
		return findings // Docker not in use
	}

	content := string(data)
	lines := strings.Split(strings.TrimSpace(content), "\n")

	if len(lines) <= 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryContainer,
			Title:       "Docker detected but no containers running",
			Description: "docker_ps.log is present but shows no containers.",
			SourceFile:  "docker_ps.log",
		})
		return findings
	}

	containerCount := len(lines) - 1 // Subtract header
	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryContainer,
		Title:       "Docker containers detected",
		Description: fmt.Sprintf("Found %d container(s) on the host.", containerCount),
		SourceFile:  "docker_ps.log",
	})

	// Check for unhealthy containers
	unhealthyRe := regexp.MustCompile(`(?i)\(unhealthy\)`)
	unhealthyCount := len(unhealthyRe.FindAllString(content, -1))
	if unhealthyCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryContainer,
			Title:       "Unhealthy Docker containers",
			Description: fmt.Sprintf("%d container(s) are in unhealthy state.", unhealthyCount),
			Suggestion:  "Review docker inspect output for failing health checks.",
			SourceFile:  "docker_ps.log",
		})
	}

	// Check for restarting containers
	restartRe := regexp.MustCompile(`(?i)Restarting`)
	restartCount := len(restartRe.FindAllString(content, -1))
	if restartCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryContainer,
			Title:       "Restarting Docker containers",
			Description: fmt.Sprintf("%d container(s) are in restart loop.", restartCount),
			SourceFile:  "docker_ps.log",
		})
	}

	return findings
}

func (a *ContainerAnalyzer) analyzeKubernetes(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	hasKubelet := archive.HasFile("k8s/kubelet_pods.yaml")
	hasKubeletConfig := archive.HasFile("k8s/kubelet_config.yaml")

	if !hasKubelet && !hasKubeletConfig {
		return findings // Not in Kubernetes
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryContainer,
		Title:       "Kubernetes environment detected",
		Description: "Kubelet data present in flare. Agent is running in a Kubernetes cluster.",
	})

	if hasKubelet {
		data, err := archive.ReadFile("k8s/kubelet_pods.yaml")
		if err == nil {
			content := string(data)
			podRe := regexp.MustCompile(`(?m)^\s*name:\s*(\S+)`)
			pods := podRe.FindAllStringSubmatch(content, -1)
			findings = append(findings, types.Finding{
				Severity:    types.SeverityInfo,
				Category:    types.CategoryContainer,
				Title:       "Kubelet pods",
				Description: fmt.Sprintf("Kubelet reports %d pod name entries in pod manifest.", len(pods)),
				SourceFile:  "k8s/kubelet_pods.yaml",
			})
		}
	}

	// Check for cluster agent
	if archive.HasFile("cluster-agent-status.log") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryContainer,
			Title:       "Cluster Agent status available",
			Description: "Cluster Agent status data is included in the flare.",
			SourceFile:  "cluster-agent-status.log",
		})
	}

	return findings
}

func (a *ContainerAnalyzer) analyzeECS(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("ecs_metadata.json")
	if err != nil {
		return findings
	}

	var ecsData map[string]interface{}
	if err := json.Unmarshal(data, &ecsData); err != nil {
		return findings
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryContainer,
		Title:       "ECS environment detected",
		Description: "Agent is running on Amazon ECS.",
		SourceFile:  "ecs_metadata.json",
	})

	return findings
}

func (a *ContainerAnalyzer) analyzeTaggerList(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("tagger-list.json")
	if err != nil {
		return findings
	}

	var taggerData map[string]interface{}
	if err := json.Unmarshal(data, &taggerData); err != nil {
		return findings
	}

	entityCount := len(taggerData)
	findings = append(findings, types.Finding{
		Severity:    types.SeverityInfo,
		Category:    types.CategoryContainer,
		Title:       "Tagger entities",
		Description: fmt.Sprintf("Tagger is tracking %d entities.", entityCount),
		SourceFile:  "tagger-list.json",
	})

	if entityCount > 5000 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryResources,
			Title:       "High tagger entity count",
			Description: fmt.Sprintf("Tagger has %d entities. This can increase memory usage.", entityCount),
			Suggestion:  "Review container exclusion/inclusion filters to reduce monitored entities.",
			SourceFile:  "tagger-list.json",
		})
	}

	return findings
}
