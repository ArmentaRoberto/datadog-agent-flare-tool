package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// SecurityAnalyzer inspects security-related data in the flare.
type SecurityAnalyzer struct{}

func (a *SecurityAnalyzer) Name() string { return "Security Analyzer" }

func (a *SecurityAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeSecrets(archive)...)
	findings = append(findings, a.analyzePermissions(archive)...)
	findings = append(findings, a.analyzeNonScrubbedFiles(archive)...)
	findings = append(findings, a.analyzeSystemProbeSecurityFiles(archive)...)

	return findings
}

func (a *SecurityAnalyzer) analyzeSecrets(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("secrets.log")
	if err != nil {
		return findings
	}

	content := string(data)

	if strings.Contains(content, "No secret_backend_command") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategorySecurity,
			Title:       "No secrets backend configured",
			Description: "The agent is not using a secrets backend for credential management.",
			SourceFile:  "secrets.log",
		})
	} else if strings.Contains(content, "secret_backend_command") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategorySecurity,
			Title:       "Secrets backend configured",
			Description: "The agent uses a secrets backend for credential management.",
			SourceFile:  "secrets.log",
		})

		if strings.Contains(content, "error") || strings.Contains(content, "Error") {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategorySecurity,
				Title:       "Secrets backend errors",
				Description: "Errors detected in secrets.log. Secrets resolution may be failing.",
				Suggestion:  "Review the secrets backend command output and permissions.",
				SourceFile:  "secrets.log",
			})
		}
	}

	return findings
}

func (a *SecurityAnalyzer) analyzePermissions(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("permissions.log")
	if err != nil {
		return findings
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	worldWritableRe := regexp.MustCompile(`-\S{6}rw`)
	worldWritableCount := 0
	for _, line := range lines {
		if worldWritableRe.MatchString(line) {
			worldWritableCount++
		}
	}

	if worldWritableCount > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategorySecurity,
			Title:       "World-writable files detected",
			Description: fmt.Sprintf("%d file(s) have world-writable permissions.", worldWritableCount),
			Suggestion:  "Restrict file permissions for agent configuration and log files.",
			SourceFile:  "permissions.log",
		})
	}

	// Check for root-owned config files
	rootOwnedRe := regexp.MustCompile(`root\s+root.*datadog\.yaml`)
	if rootOwnedRe.MatchString(content) {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategorySecurity,
			Title:       "Config files are root-owned",
			Description: "datadog.yaml is owned by root, which is the expected configuration.",
			SourceFile:  "permissions.log",
		})
	}

	return findings
}

func (a *SecurityAnalyzer) analyzeNonScrubbedFiles(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	data, err := archive.ReadFile("non_scrubbed_files.json")
	if err != nil {
		return findings
	}

	content := strings.TrimSpace(string(data))
	if content == "[]" || content == "" {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategorySecurity,
			Title:       "All files scrubbed",
			Description: "All files in the flare were scrubbed for sensitive data.",
			SourceFile:  "non_scrubbed_files.json",
		})
	} else {
		// Count non-scrubbed files
		fileRe := regexp.MustCompile(`"([^"]+)"`)
		files := fileRe.FindAllStringSubmatch(content, -1)
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategorySecurity,
			Title:       "Non-scrubbed files in flare",
			Description: fmt.Sprintf("%d file(s) were NOT scrubbed. These may contain sensitive data.", len(files)),
			Suggestion:  "Review non_scrubbed_files.json before sharing the flare with third parties.",
			SourceFile:  "non_scrubbed_files.json",
		})
	}

	return findings
}

func (a *SecurityAnalyzer) analyzeSystemProbeSecurityFiles(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	// Check SELinux status
	if archive.HasFile("system-probe/selinux_sestatus.log") {
		data, err := archive.ReadFile("system-probe/selinux_sestatus.log")
		if err == nil {
			content := string(data)
			if strings.Contains(content, "enforcing") {
				findings = append(findings, types.Finding{
					Severity:    types.SeverityInfo,
					Category:    types.CategorySecurity,
					Title:       "SELinux is enforcing",
					Description: "SELinux is in enforcing mode. This may affect agent operations.",
					Suggestion:  "Ensure SELinux policies allow the agent to operate. Check system-probe/selinux_semodule_list.log.",
					SourceFile:  "system-probe/selinux_sestatus.log",
				})
			}
		}
	}

	return findings
}
