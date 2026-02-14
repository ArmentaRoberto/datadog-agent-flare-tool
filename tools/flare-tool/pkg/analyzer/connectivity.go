package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// ConnectivityAnalyzer checks for network and connectivity issues.
type ConnectivityAnalyzer struct{}

func (a *ConnectivityAnalyzer) Name() string { return "Connectivity Analyzer" }

func (a *ConnectivityAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeDiagnose(archive)...)
	findings = append(findings, a.analyzeExpvarForwarder(archive)...)
	findings = append(findings, a.analyzeEnvVars(archive)...)

	return findings
}

func (a *ConnectivityAnalyzer) analyzeDiagnose(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("diagnose.log")
	if err != nil {
		return findings
	}

	content := string(data)

	// Count pass/fail/warn
	passRe := regexp.MustCompile(`(?i)\bPASS\b`)
	failRe := regexp.MustCompile(`(?i)\bFAIL\b`)
	warnRe := regexp.MustCompile(`(?i)\bWARNING\b`)

	passCount := len(passRe.FindAllString(content, -1))
	failCount := len(failRe.FindAllString(content, -1))
	warnCount := len(warnRe.FindAllString(content, -1))

	if failCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryConnectivity,
			Title:       "Diagnose failures detected",
			Description: fmt.Sprintf("Diagnostics: %d PASS, %d FAIL, %d WARNING", passCount, failCount, warnCount),
			Suggestion:  "Review diagnose.log for specific connectivity and configuration failures.",
			SourceFile:  "diagnose.log",
		})
	} else if passCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConnectivity,
			Title:       "Diagnostics passed",
			Description: fmt.Sprintf("All %d diagnostic checks passed (%d warnings).", passCount, warnCount),
			SourceFile:  "diagnose.log",
		})
	}

	// Look for specific connectivity diagnose results
	if strings.Contains(content, "connectivity-datadog-core-endpoints") {
		if strings.Contains(content, "FAIL") && strings.Contains(content, "datadoghq") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityCritical,
				Category:    types.CategoryConnectivity,
				Title:       "Cannot reach Datadog core endpoints",
				Description: "The agent cannot connect to Datadog intake endpoints.",
				Suggestion:  "Check DNS resolution, proxy settings, and firewall rules for *.datadoghq.com.",
				SourceFile:  "diagnose.log",
			})
		}
	}

	return findings
}

func (a *ConnectivityAnalyzer) analyzeExpvarForwarder(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("expvar/forwarder")
	if err != nil {
		return findings
	}

	content := string(data)

	// Check for connection errors in expvar
	if strings.Contains(content, "\"ConnectionErrors\"") {
		errRe := regexp.MustCompile(`"ConnectionErrors"\s*:\s*{([^}]+)}`)
		if m := errRe.FindStringSubmatch(content); len(m) > 1 {
			errBlock := m[1]
			if !strings.Contains(errBlock, ": 0") || strings.Contains(errBlock, ": [1-9]") {
				findings = append(findings, types.Finding{
					Severity:    types.SeverityError,
					Category:    types.CategoryConnectivity,
					Title:       "Forwarder connection errors in expvars",
					Description: "The forwarder has recorded connection errors when sending data to Datadog.",
					Suggestion:  "Check network connectivity, proxy configuration, and DNS resolution.",
					SourceFile:  "expvar/forwarder",
				})
			}
		}
	}

	// Check transactions metrics
	droppedRe := regexp.MustCompile(`"TransactionsDropped"\s*:\s*(\d+)`)
	if m := droppedRe.FindStringSubmatch(content); len(m) > 1 && m[1] != "0" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryConnectivity,
			Title:       "Transactions dropped by forwarder",
			Description: fmt.Sprintf("%s transactions dropped. Data is being lost.", m[1]),
			Suggestion:  "The forwarder cannot keep up or reach Datadog. Check connectivity and agent resources.",
			SourceFile:  "expvar/forwarder",
		})
	}

	return findings
}

func (a *ConnectivityAnalyzer) analyzeEnvVars(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("envvars.log")
	if err != nil {
		return findings
	}

	content := string(data)

	// Check for proxy env vars
	proxyVars := []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "DD_PROXY_HTTP", "DD_PROXY_HTTPS"}
	var detectedProxy []string
	for _, v := range proxyVars {
		re := regexp.MustCompile(v + `=(\S+)`)
		if m := re.FindStringSubmatch(content); len(m) > 1 {
			detectedProxy = append(detectedProxy, fmt.Sprintf("%s=%s", v, m[1]))
		}
	}

	if len(detectedProxy) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConnectivity,
			Title:       "Proxy environment variables detected",
			Description: fmt.Sprintf("Found proxy settings: %s", strings.Join(detectedProxy, ", ")),
			Suggestion:  "Ensure proxy allows connections to Datadog endpoints.",
			SourceFile:  "envvars.log",
		})
	}

	// Check for DD_SITE
	siteRe := regexp.MustCompile(`DD_SITE=(\S+)`)
	if m := siteRe.FindStringSubmatch(content); len(m) > 1 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConfig,
			Title:       "DD_SITE environment variable set",
			Description: fmt.Sprintf("DD_SITE=%s", m[1]),
			SourceFile:  "envvars.log",
		})
	}

	return findings
}
