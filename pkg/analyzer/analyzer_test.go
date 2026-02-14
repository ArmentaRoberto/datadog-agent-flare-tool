package analyzer

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

func createTestArchive(t *testing.T, files map[string]string) *extractor.FlareArchive {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-flare.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	f.Close()

	archive, err := extractor.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { archive.Close() })
	return archive
}

func findFinding(findings []types.Finding, title string) *types.Finding {
	for i, f := range findings {
		if f.Title == title {
			return &findings[i]
		}
	}
	return nil
}

func hasFindingWithSeverity(findings []types.Finding, sev types.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func TestConfigAnalyzer_MissingConfig(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/status.log": "Agent (v7.52.0)",
	})

	a := &ConfigAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Missing main configuration file")
	if f == nil {
		t.Fatal("expected 'Missing main configuration file' finding")
	}
	if f.Severity != types.SeverityError {
		t.Errorf("expected ERROR severity, got %v", f.Severity)
	}
}

func TestConfigAnalyzer_EmptyAPIKey(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/etc/datadog.yaml": "api_key: \nsite: datadoghq.com\n",
	})

	a := &ConfigAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "API key is empty")
	if f == nil {
		t.Fatal("expected 'API key is empty' finding")
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", f.Severity)
	}
}

func TestConfigAnalyzer_DebugLogLevel(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/etc/datadog.yaml": "api_key: \"***abc\"\nlog_level: debug\n",
	})

	a := &ConfigAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, `Log level set to "debug"`)
	if f == nil {
		t.Fatal("expected debug log level warning")
	}
	if f.Severity != types.SeverityWarning {
		t.Errorf("expected WARNING severity, got %v", f.Severity)
	}
}

func TestStatusAnalyzer_Version(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/status.log": "Agent (v7.52.1)\nHostname: myhostname\n",
	})

	a := &StatusAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Agent version detected")
	if f == nil {
		t.Fatal("expected 'Agent version detected' finding")
	}
}

func TestStatusAnalyzer_InvalidAPIKey(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/status.log": "Agent (v7.52.1)\nAPI Key invalid\n",
	})

	a := &StatusAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Invalid API key")
	if f == nil {
		t.Fatal("expected 'Invalid API key' finding")
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %v", f.Severity)
	}
}

func TestHealthAnalyzer_Unhealthy(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/health.yaml": "collector: healthy\nforwarder: unhealthy\n",
	})

	a := &HealthAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Unhealthy components detected")
	if f == nil {
		t.Fatal("expected 'Unhealthy components detected' finding")
	}
	if f.Severity != types.SeverityError {
		t.Errorf("expected ERROR, got %v", f.Severity)
	}
}

func TestLogAnalyzer_Panic(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": "2024-01-15 | CORE | ERROR | something failed\n2024-01-15 | CORE | panic: runtime error\n",
	})

	a := &LogAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Panics detected in Core Agent")
	if f == nil {
		t.Fatal("expected panic finding")
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %v", f.Severity)
	}
}

func TestConnectivityAnalyzer_DiagnoseFailures(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/diagnose.log": "PASS - endpoint A\nFAIL - endpoint B\n",
	})

	a := &ConnectivityAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Diagnose failures detected")
	if f == nil {
		t.Fatal("expected diagnose failures finding")
	}
	if f.Severity != types.SeverityError {
		t.Errorf("expected ERROR, got %v", f.Severity)
	}
}

func TestCompletenessAnalyzer_MissingFiles(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/status.log": "content",
		// Missing most expected files
	})

	a := &CompletenessAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Missing expected flare files")
	if f == nil {
		t.Fatal("expected 'Missing expected flare files' finding")
	}
	if f.Severity != types.SeverityError {
		t.Errorf("expected ERROR, got %v", f.Severity)
	}
}

func TestCompletenessAnalyzer_AllPresent(t *testing.T) {
	files := map[string]string{
		"myhost/status.log":               "content",
		"myhost/config-check.log":         "content",
		"myhost/health.yaml":              "content",
		"myhost/runtime_config_dump.yaml":  "content",
		"myhost/envvars.log":              "content",
		"myhost/diagnose.log":             "content",
		"myhost/etc/datadog.yaml":         "api_key: test",
	}
	archive := createTestArchive(t, files)

	a := &CompletenessAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "All expected files present")
	if f == nil {
		t.Fatal("expected 'All expected files present' finding")
	}
}

func TestContainerAnalyzer_Docker(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/docker_ps.log": "CONTAINER ID  IMAGE\nabc  nginx  Up 5 days\ndef  redis  Up 2 days (unhealthy)\n",
	})

	a := &ContainerAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "Docker containers detected")
	if f == nil {
		t.Fatal("expected Docker containers finding")
	}

	f = findFinding(findings, "Unhealthy Docker containers")
	if f == nil {
		t.Fatal("expected unhealthy Docker container finding")
	}
}

func TestSecurityAnalyzer_NoSecretsBackend(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/secrets.log": "No secret_backend_command set",
	})

	a := &SecurityAnalyzer{}
	findings := a.Analyze(archive)

	f := findFinding(findings, "No secrets backend configured")
	if f == nil {
		t.Fatal("expected no secrets backend finding")
	}
}

func TestAllAnalyzersRun(t *testing.T) {
	// Create a complete flare with all files
	archive := createTestArchive(t, map[string]string{
		"myhost/status.log":               "Agent (v7.52.0)\nHostname: test\n",
		"myhost/config-check.log":         "=== cpu ===\nOK\n",
		"myhost/health.yaml":              "collector: healthy\n",
		"myhost/runtime_config_dump.yaml":  "api_key: ***\n",
		"myhost/envvars.log":              "DD_SITE=datadoghq.com\n",
		"myhost/diagnose.log":             "PASS - all ok\n",
		"myhost/etc/datadog.yaml":         "api_key: \"***abc\"\nsite: datadoghq.com\n",
		"myhost/logs/agent.log":           "2024-01-15 | INFO | started\n",
		"myhost/go-routine-dump.log":       "goroutine 1 [running]:\nmain()\n",
		"myhost/secrets.log":              "No secret_backend_command set\n",
		"myhost/permissions.log":           "-rw-r--r-- root root datadog.yaml\n",
		"myhost/non_scrubbed_files.json":   "[]",
		"myhost/metadata/host.json":        "{}",
		"myhost/metadata/inventory/agent.json": "{}",
		"myhost/install_info.log":          "install_method: apt",
		"myhost/version-history.json":      "{}",
		"myhost/telemetry.log":            "metrics here",
	})

	totalFindings := 0
	for _, a := range Registry {
		findings := a.Analyze(archive)
		totalFindings += len(findings)
	}

	if totalFindings == 0 {
		t.Error("expected at least some findings from running all analyzers")
	}

	// Verify all 11 analyzers are registered
	if len(Registry) != 11 {
		t.Errorf("expected 11 registered analyzers, got %d", len(Registry))
	}
}

func TestYamlUtil(t *testing.T) {
	data := []byte(`
api_key: "***abc"
site: datadoghq.com
log_level: debug
tags:
  - env:prod
  - service:web
apm_config:
  enabled: false
`)

	// Test yamlGetValue
	if v, ok := yamlGetValue(data, "site"); !ok || v != "datadoghq.com" {
		t.Errorf("yamlGetValue(site) = %q, %v", v, ok)
	}

	if v, ok := yamlGetValue(data, "log_level"); !ok || v != "debug" {
		t.Errorf("yamlGetValue(log_level) = %q, %v", v, ok)
	}

	// Test yamlHasKey
	if !yamlHasKey(data, "api_key") {
		t.Error("expected yamlHasKey(api_key) to be true")
	}
	if yamlHasKey(data, "nonexistent") {
		t.Error("expected yamlHasKey(nonexistent) to be false")
	}

	// Test yamlCountListItems
	count := yamlCountListItems(data, "tags")
	if count != 2 {
		t.Errorf("yamlCountListItems(tags) = %d, expected 2", count)
	}

	// Test yamlGetNestedValue
	if v, ok := yamlGetNestedValue(data, "apm_config", "enabled"); !ok || v != "false" {
		t.Errorf("yamlGetNestedValue(apm_config, enabled) = %q, %v", v, ok)
	}
}
