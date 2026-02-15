package analyzer

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// Verify all 13 analyzers are registered (11 original + ExpvarDeep + LogInsight)
	if len(Registry) != 13 {
		t.Errorf("expected 13 registered analyzers, got %d", len(Registry))
	}
}

// ---------------------------------------------------------------------------
// ExpvarDeepAnalyzer tests
// ---------------------------------------------------------------------------

func TestExpvarDeep_ForwarderDataLoss(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/forwarder": `Transactions:
  Success: 10000
  Errors: 500
  Dropped: 200
  Retried: 150
  RetryQueueSize: 25
  HighPriorityQueueFull: 0
  ErrorsByType:
    DNSErrors: 50
    TLSErrors: 300
    ConnectionErrors: 100
    WroteRequestErrors: 0
    SentRequestErrors: 0
  DroppedByEndpoint:
    v1-series: 150
    v1-intake: 50
  HTTPErrorsByCode:
    403: 200
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	// Should detect data loss
	var foundDataLoss bool
	for _, f := range findings {
		if strings.Contains(f.Title, "data loss") || strings.Contains(f.Title, "success rate") {
			foundDataLoss = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR or higher for data loss, got %v", f.Severity)
			}
			// Should mention TLS as dominant error
			if !strings.Contains(f.Description, "TLS") {
				t.Error("expected TLS to be mentioned in error breakdown")
			}
			// Should mention per-endpoint drops
			if !strings.Contains(f.Description, "v1-series") {
				t.Error("expected per-endpoint breakdown")
			}
			// Should mention HTTP 403
			if !strings.Contains(f.Description, "403") {
				t.Error("expected HTTP 403 error code")
			}
			break
		}
	}
	if !foundDataLoss {
		t.Fatal("expected forwarder data loss finding")
	}

	// Should detect retry queue
	var foundRetryQueue bool
	for _, f := range findings {
		if strings.Contains(f.Title, "retry queue") {
			foundRetryQueue = true
			break
		}
	}
	if !foundRetryQueue {
		t.Error("expected retry queue finding")
	}
}

func TestExpvarDeep_ForwarderHealthy(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/forwarder": `Transactions:
  Success: 50000
  Errors: 0
  Dropped: 0
  Retried: 0
  RetryQueueSize: 0
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	var found bool
	for _, f := range findings {
		if strings.Contains(f.Title, "100% success") {
			found = true
			if f.Severity != types.SeverityInfo {
				t.Errorf("expected INFO for healthy forwarder, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected healthy forwarder finding")
	}
}

func TestExpvarDeep_AggregatorCardinality(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/aggregator": `DogstatsdContexts: 75000
DogstatsdContextsByMtype:
  Gauge: 25000
  Counter: 20000
  Distribution: 30000
SeriesFlushed: 100000
SeriesFlushErrors: 500
EventsFlushed: 1000
EventsFlushErrors: 0
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	// Should detect high cardinality
	var foundCardinality bool
	for _, f := range findings {
		if strings.Contains(f.Title, "cardinality") {
			foundCardinality = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR or higher for 75k contexts, got %v", f.Severity)
			}
			if !strings.Contains(f.Description, "Distribution") {
				t.Error("expected metric type breakdown")
			}
			break
		}
	}
	if !foundCardinality {
		t.Fatal("expected cardinality finding")
	}
}

func TestExpvarDeep_DogstatsdParseErrors(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/dogstatsd": `MetricPackets: 10000
MetricParseErrors: 1000
EventPackets: 100
EventParseErrors: 0
ServiceCheckPackets: 50
ServiceCheckParseErrors: 0
UnterminatedMetricErrors: 50
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	var found bool
	for _, f := range findings {
		if strings.Contains(f.Title, "parse error") {
			found = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR for >5%% parse errors, got %v", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected DogStatsD parse error finding")
	}
}

func TestExpvarDeep_MemoryAnalysis(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/agent": `memstats:
  Alloc: 524288000
  TotalAlloc: 10737418240
  Sys: 2684354560
  HeapAlloc: 524288000
  HeapInuse: 536870912
  HeapIdle: 268435456
  NumGC: 5000
  PauseTotalNs: 100000000000
goroutines: 350
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	var found bool
	for _, f := range findings {
		if strings.Contains(f.Title, "memory") || strings.Contains(f.Title, "Memory") {
			found = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR for >2GB memory, got %v", f.Severity)
			}
			if !strings.Contains(f.Description, "GC") {
				t.Error("expected GC info in memory analysis")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected memory analysis finding")
	}
}

func TestExpvarDeep_RunnerCheckHealth(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/runner": `Runs: 1000
Errors: 150
Warnings: 30
Running: 2
Checks:
  postgres:
    RunCount: 500
    TotalErrors: 100
    TotalWarnings: 5
    AverageExecutionTime: 25000000000
    LastExecutionTime: 23000000000
    LastError: "connection refused to 10.0.0.5:5432"
  cpu:
    RunCount: 500
    TotalErrors: 0
    TotalWarnings: 0
    AverageExecutionTime: 15000000
    LastExecutionTime: 14000000
    LastError: ""
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	// Should detect unhealthy checks
	var foundUnhealthy bool
	for _, f := range findings {
		if strings.Contains(f.Title, "runtime errors") {
			foundUnhealthy = true
			if !strings.Contains(f.Description, "postgres") {
				t.Error("expected postgres check in unhealthy list")
			}
			if !strings.Contains(f.Description, "connection refused") {
				t.Error("expected last error message")
			}
			break
		}
	}
	if !foundUnhealthy {
		t.Fatal("expected unhealthy check finding")
	}

	// Should detect slow checks
	var foundSlow bool
	for _, f := range findings {
		if strings.Contains(f.Title, "slow check") || strings.Contains(f.Title, "Slow") {
			foundSlow = true
			if !strings.Contains(f.Description, "postgres") {
				t.Error("expected postgres in slow checks")
			}
			break
		}
	}
	if !foundSlow {
		t.Fatal("expected slow check finding")
	}
}

func TestExpvarDeep_LogsAgentHealth(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/expvar/logs-agent": `LogsDecoded: 50000
LogsProcessed: 50000
LogsSent: 49000
LogsTruncated: 500
DestinationErrors: 100
BytesSent: 104857600
EncodedBytesSent: 20971520
BytesMissed: 5242880
RetryCount: 50
SenderLatency: 2500
`,
	})

	a := &ExpvarDeepAnalyzer{}
	findings := a.Analyze(archive)

	var found bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Logs agent") || strings.Contains(f.Title, "logs agent") {
			found = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR for destination errors, got %v", f.Severity)
			}
			if !strings.Contains(f.Description, "Decoded") {
				t.Error("expected pipeline metrics in description")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected logs agent health finding")
	}
}

// ---------------------------------------------------------------------------
// LogInsightAnalyzer tests
// ---------------------------------------------------------------------------

func TestLogInsight_ErrorClassification(t *testing.T) {
	// Create logs with various error types
	var logContent strings.Builder
	// Network errors
	for i := 0; i < 20; i++ {
		logContent.WriteString("2024-01-15 14:30:00 UTC | CORE | ERROR | (forwarder.go:54 in send) | connection refused to 10.0.0.5:8126\n")
	}
	// TLS errors
	for i := 0; i < 10; i++ {
		logContent.WriteString("2024-01-15 14:31:00 UTC | CORE | ERROR | (http.go:100 in post) | TLS handshake error: certificate has expired\n")
	}
	// Permission errors
	for i := 0; i < 5; i++ {
		logContent.WriteString("2024-01-15 14:32:00 UTC | CORE | ERROR | (check.go:50 in run) | permission denied reading /var/log/syslog\n")
	}

	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": logContent.String(),
	})

	a := &LogInsightAnalyzer{}
	findings := a.Analyze(archive)

	// Should classify errors
	var foundClassification bool
	for _, f := range findings {
		if strings.Contains(f.Title, "classification") || strings.Contains(f.Title, "Classification") {
			foundClassification = true
			if !strings.Contains(f.Description, "Network") {
				t.Error("expected Network error class")
			}
			if !strings.Contains(f.Description, "TLS") {
				t.Error("expected TLS error class")
			}
			if !strings.Contains(f.Description, "Permission") {
				t.Error("expected Permission error class")
			}
			break
		}
	}
	if !foundClassification {
		t.Fatal("expected error classification finding")
	}

	// Should have root cause inference
	var foundRootCause bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Root cause") || strings.Contains(f.Title, "root cause") {
			foundRootCause = true
			break
		}
	}
	if !foundRootCause {
		t.Fatal("expected root cause analysis finding")
	}
}

func TestLogInsight_ErrorSpike(t *testing.T) {
	var logContent strings.Builder
	// Normal period: 2 errors per 5 minutes
	for i := 0; i < 10; i++ {
		ts := fmt.Sprintf("2024-01-15 14:%02d:00 UTC", i*5)
		logContent.WriteString(ts + " | CORE | ERROR | (check.go:50 in run) | some error\n")
		logContent.WriteString(ts + " | CORE | ERROR | (check.go:51 in run) | another error\n")
		logContent.WriteString(ts + " | CORE | INFO | (main.go:10 in main) | heartbeat\n")
	}
	// Spike period: 100 errors in 5 minutes
	for i := 0; i < 100; i++ {
		logContent.WriteString("2024-01-15 15:00:00 UTC | CORE | ERROR | (forwarder.go:54 in send) | connection refused to 10.0.0.5:443\n")
	}

	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": logContent.String(),
	})

	a := &LogInsightAnalyzer{}
	findings := a.Analyze(archive)

	var foundSpike bool
	for _, f := range findings {
		if strings.Contains(f.Title, "spike") || strings.Contains(f.Title, "Spike") {
			foundSpike = true
			if f.Severity < types.SeverityError {
				t.Errorf("expected ERROR severity for spike, got %v", f.Severity)
			}
			break
		}
	}
	if !foundSpike {
		t.Fatal("expected error spike finding")
	}
}

func TestLogInsight_CrossComponentCorrelation(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": strings.Repeat(
			"2024-01-15 14:30:00 UTC | CORE | ERROR | (forwarder.go:54 in send) | connection refused\n", 20),
		"myhost/logs/trace-agent.log": strings.Repeat(
			"2024-01-15 14:30:00 UTC | TRACE | ERROR | (writer.go:100 in flush) | connection refused\n", 15),
	})

	a := &LogInsightAnalyzer{}
	findings := a.Analyze(archive)

	var foundCorrelation bool
	for _, f := range findings {
		if strings.Contains(f.Title, "correlation") || strings.Contains(f.Title, "Correlation") {
			foundCorrelation = true
			break
		}
	}
	if !foundCorrelation {
		t.Fatal("expected cross-component correlation finding")
	}
}

func TestLogInsight_CrashExtraction(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": `2024-01-15 14:30:00 UTC | CORE | INFO | starting
2024-01-15 14:30:01 UTC | CORE | ERROR | panic: runtime error: invalid memory address
goroutine 1 [running]:
github.com/DataDog/datadog-agent/pkg/aggregator.(*BufferedAggregator).Flush(0xc0001a2000)
	/go/src/github.com/DataDog/datadog-agent/pkg/aggregator/aggregator.go:432
main.main()
	/go/src/github.com/DataDog/datadog-agent/cmd/agent/main.go:100

`,
	})

	a := &LogInsightAnalyzer{}
	findings := a.Analyze(archive)

	var foundCrash bool
	for _, f := range findings {
		if strings.Contains(f.Title, "crash") || strings.Contains(f.Title, "Crash") {
			foundCrash = true
			if f.Severity != types.SeverityCritical {
				t.Errorf("expected CRITICAL for crash, got %v", f.Severity)
			}
			if !strings.Contains(f.Description, "aggregator") {
				t.Error("expected stack frame reference in crash description")
			}
			break
		}
	}
	if !foundCrash {
		t.Fatal("expected crash finding")
	}
}

func TestLogInsight_NoErrorsReturnsNil(t *testing.T) {
	archive := createTestArchive(t, map[string]string{
		"myhost/logs/agent.log": "2024-01-15 14:30:00 UTC | CORE | INFO | all good\n",
	})

	a := &LogInsightAnalyzer{}
	findings := a.Analyze(archive)

	if len(findings) != 0 {
		t.Errorf("expected no findings for clean logs, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Expvar helper function tests
// ---------------------------------------------------------------------------

func TestExtractBlock(t *testing.T) {
	content := `Transactions:
  Success: 12345
  Errors: 5
  ConnectionEvents:
    DNSSuccess: 100
    ConnectSuccess: 200
OtherKey: value
`
	block := extractBlock(content, "Transactions")
	if block == "" {
		t.Fatal("expected non-empty block for Transactions")
	}
	if !strings.Contains(block, "Success: 12345") {
		t.Error("expected Success in Transactions block")
	}
	if strings.Contains(block, "OtherKey") {
		t.Error("Transactions block should not contain OtherKey")
	}
}

func TestBlockInt(t *testing.T) {
	block := "  Success: 12345\n  Errors: 0\n"
	if v := blockInt(block, "Success"); v != 12345 {
		t.Errorf("blockInt(Success) = %d, want 12345", v)
	}
	if v := blockInt(block, "Errors"); v != 0 {
		t.Errorf("blockInt(Errors) = %d, want 0", v)
	}
	if v := blockInt(block, "Missing"); v != 0 {
		t.Errorf("blockInt(Missing) = %d, want 0", v)
	}
}

func TestBlockSection(t *testing.T) {
	content := `DroppedByEndpoint:
  v1-series: 150
  v1-intake: 50
OtherKey: value
`
	section := blockSection(content, "DroppedByEndpoint")
	if len(section) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(section))
	}
	if section["v1-series"] != 150 {
		t.Errorf("v1-series = %d, want 150", section["v1-series"])
	}
	if section["v1-intake"] != 50 {
		t.Errorf("v1-intake = %d, want 50", section["v1-intake"])
	}
}

func TestFmtCount(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
	}
	for _, tt := range tests {
		got := fmtCount(tt.input)
		if got != tt.want {
			t.Errorf("fmtCount(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFmtBytes(t *testing.T) {
	if got := fmtBytes(500); got != "500 B" {
		t.Errorf("fmtBytes(500) = %q", got)
	}
	if got := fmtBytes(1536); !strings.Contains(got, "KB") {
		t.Errorf("fmtBytes(1536) = %q, expected KB", got)
	}
	if got := fmtBytes(1048576); !strings.Contains(got, "MB") {
		t.Errorf("fmtBytes(1048576) = %q, expected MB", got)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		msg  string
		want errorClass
	}{
		{"connection refused to 10.0.0.5:5432", errClassNetwork},
		{"TLS handshake error: certificate has expired", errClassTLS},
		{"permission denied reading /var/log/syslog", errClassPermission},
		{"context deadline exceeded", errClassTimeout},
		{"panic: runtime error: invalid memory address", errClassCrash},
		{"out of memory", errClassResource},
		{"invalid config key: foobar", errClassConfig},
		{"something went wrong", errClassUnknown},
	}
	for _, tt := range tests {
		got := classifyError(tt.msg)
		if got != tt.want {
			t.Errorf("classifyError(%q) = %q, want %q", tt.msg, got, tt.want)
		}
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
