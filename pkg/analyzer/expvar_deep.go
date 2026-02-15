package analyzer

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// ExpvarDeepAnalyzer performs deep analysis of all expvar runtime counters
// to surface insights that require understanding of counter relationships,
// rates, and thresholds — the kind of analysis a senior support engineer
// would do manually.
type ExpvarDeepAnalyzer struct{}

func (a *ExpvarDeepAnalyzer) Name() string { return "Expvar Deep Analyzer" }

func (a *ExpvarDeepAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	findings = append(findings, a.analyzeForwarderHealth(archive)...)
	findings = append(findings, a.analyzeAggregatorHealth(archive)...)
	findings = append(findings, a.analyzeDogstatsdHealth(archive)...)
	findings = append(findings, a.analyzeRunnerHealth(archive)...)
	findings = append(findings, a.analyzeLogsAgentHealth(archive)...)
	findings = append(findings, a.analyzeMemoryAndRuntime(archive)...)

	return findings
}

// ---------------------------------------------------------------------------
// Forwarder deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeForwarderHealth(archive *extractor.FlareArchive) []types.Finding {
	data, err := archive.ReadFile("expvar/forwarder")
	if err != nil {
		return nil
	}
	content := string(data)
	var findings []types.Finding

	// Extract the Transactions block (could be top-level or nested)
	txBlock := extractBlock(content, "Transactions")
	if txBlock == "" {
		// Try flat format where counters are at top level
		txBlock = content
	}

	success := blockInt(txBlock, "Success")
	errors := blockInt(txBlock, "Errors")
	dropped := blockInt(txBlock, "Dropped")
	retried := blockInt(txBlock, "Retried")
	retryQueueSize := blockInt(txBlock, "RetryQueueSize")
	highPriorityQueueFull := blockInt(txBlock, "HighPriorityQueueFull")
	requeued := blockInt(txBlock, "Requeued")

	total := success + errors + dropped
	if total == 0 {
		return nil
	}

	successRate := float64(success) / float64(total) * 100

	// Transaction health score
	if dropped > 0 {
		var desc strings.Builder
		fmt.Fprintf(&desc, "Transaction success rate: %.1f%% (%s success / %s total)\n",
			successRate, fmtCount(success), fmtCount(total))
		fmt.Fprintf(&desc, "%s transactions DROPPED — active data loss\n", fmtCount(dropped))
		if retried > 0 {
			fmt.Fprintf(&desc, "%s transactions retried\n", fmtCount(retried))
		}

		// Error type breakdown
		errBlock := extractBlock(txBlock, "ErrorsByType")
		if errBlock != "" {
			desc.WriteString(a.formatErrorBreakdown(errBlock, errors))
		}

		// Per-endpoint drops
		droppedByEP := blockSection(txBlock, "DroppedByEndpoint")
		if len(droppedByEP) > 0 {
			desc.WriteString("\nDropped by endpoint:\n")
			for ep, count := range droppedByEP {
				if count > 0 {
					pct := float64(count) / float64(dropped) * 100
					fmt.Fprintf(&desc, "  %s: %s (%.1f%%)\n", ep, fmtCount(count), pct)
				}
			}
		}

		// HTTP error codes
		httpByCode := blockSection(txBlock, "HTTPErrorsByCode")
		if len(httpByCode) > 0 {
			desc.WriteString("\nHTTP errors by status code:\n")
			for code, count := range httpByCode {
				if count > 0 {
					hint := httpCodeHint(code)
					fmt.Fprintf(&desc, "  %s: %s%s\n", code, fmtCount(count), hint)
				}
			}
		}

		sev := types.SeverityError
		if successRate < 50 {
			sev = types.SeverityCritical
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryConnectivity,
			Title:       fmt.Sprintf("Forwarder data loss: %.1f%% success rate", successRate),
			Description: desc.String(),
			Suggestion:  a.forwarderSuggestion(errBlock),
			SourceFile:  "expvar/forwarder",
		})
	} else if errors > 0 {
		var desc strings.Builder
		fmt.Fprintf(&desc, "Transaction success rate: %.1f%% (%s success, %s errors, 0 dropped)\n",
			successRate, fmtCount(success), fmtCount(errors))
		if retried > 0 {
			fmt.Fprintf(&desc, "%s transactions retried — intermittent connectivity issues\n", fmtCount(retried))
		}
		errBlock := extractBlock(txBlock, "ErrorsByType")
		if errBlock != "" {
			desc.WriteString(a.formatErrorBreakdown(errBlock, errors))
		}

		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryConnectivity,
			Title:       fmt.Sprintf("Forwarder errors detected: %.1f%% success rate", successRate),
			Description: desc.String(),
			Suggestion:  a.forwarderSuggestion(errBlock),
			SourceFile:  "expvar/forwarder",
		})
	} else {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConnectivity,
			Title:       "Forwarder healthy: 100% success rate",
			Description: fmt.Sprintf("All %s transactions successful. No errors or drops.", fmtCount(success)),
			SourceFile:  "expvar/forwarder",
		})
	}

	// Retry queue health
	if retryQueueSize > 0 {
		sev := types.SeverityWarning
		if retryQueueSize > 100 {
			sev = types.SeverityError
		}
		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryConnectivity,
			Title:       fmt.Sprintf("Forwarder retry queue: %s pending", fmtCount(retryQueueSize)),
			Description: "Transactions are queued for retry, indicating ongoing connectivity problems.",
			Suggestion:  "The retry queue should drain when connectivity is restored. If it keeps growing, check network path to Datadog.",
			SourceFile:  "expvar/forwarder",
		})
	}

	// High priority queue full
	if highPriorityQueueFull > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryConnectivity,
			Title:       "Forwarder high-priority queue overflows",
			Description: fmt.Sprintf("High-priority queue was full %s time(s). Critical payloads may have been dropped.", fmtCount(highPriorityQueueFull)),
			Suggestion:  "This typically means the forwarder cannot send data fast enough. Check network bandwidth and agent resource limits.",
			SourceFile:  "expvar/forwarder",
		})
	}

	// Requeued transactions
	if requeued > 0 && dropped == 0 && errors == 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryConnectivity,
			Title:       fmt.Sprintf("Forwarder requeued %s transactions", fmtCount(requeued)),
			Description: "Transactions were requeued but eventually succeeded. Transient issues resolved.",
			SourceFile:  "expvar/forwarder",
		})
	}

	// Per-endpoint success analysis
	successByEP := blockSection(txBlock, "SuccessByEndpoint")
	inputByEP := blockSection(txBlock, "InputCountByEndpoint")
	if len(successByEP) > 0 && len(inputByEP) > 0 {
		var epIssues []string
		for ep, input := range inputByEP {
			if input == 0 {
				continue
			}
			succ, ok := successByEP[ep]
			if !ok {
				succ = 0
			}
			epRate := float64(succ) / float64(input) * 100
			if epRate < 95 {
				epIssues = append(epIssues, fmt.Sprintf("  %s: %.1f%% success (%s/%s)", ep, epRate, fmtCount(succ), fmtCount(input)))
			}
		}
		if len(epIssues) > 0 {
			sort.Strings(epIssues)
			findings = append(findings, types.Finding{
				Severity:    types.SeverityError,
				Category:    types.CategoryConnectivity,
				Title:       "Per-endpoint delivery failures",
				Description: fmt.Sprintf("Endpoints with <95%% success rate:\n%s", strings.Join(epIssues, "\n")),
				Suggestion:  "Some Datadog intake endpoints are unreachable. This may indicate selective blocking by firewall/proxy.",
				SourceFile:  "expvar/forwarder",
			})
		}
	}

	// API key status
	apiKeyStatus := extractBlock(content, "APIKeyStatus")
	if apiKeyStatus != "" && strings.Contains(strings.ToLower(apiKeyStatus), "invalid") {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityCritical,
			Category:    types.CategoryConnectivity,
			Title:       "API key validation failed (expvar)",
			Description: "The forwarder's API key status shows the key is invalid.",
			Suggestion:  "Verify API key at https://app.datadoghq.com/organization-settings/api-keys",
			SourceFile:  "expvar/forwarder",
		})
	}

	return findings
}

func (a *ExpvarDeepAnalyzer) formatErrorBreakdown(errBlock string, totalErrors int64) string {
	var b strings.Builder
	dnsErrors := blockInt(errBlock, "DNSErrors")
	tlsErrors := blockInt(errBlock, "TLSErrors")
	connErrors := blockInt(errBlock, "ConnectionErrors")
	wroteErrors := blockInt(errBlock, "WroteRequestErrors")
	sentErrors := blockInt(errBlock, "SentRequestErrors")

	errTypes := []struct {
		name  string
		count int64
	}{
		{"TLS errors", tlsErrors},
		{"Connection errors", connErrors},
		{"DNS errors", dnsErrors},
		{"Write errors", wroteErrors},
		{"Send errors", sentErrors},
	}

	// Sort by count descending
	sort.Slice(errTypes, func(i, j int) bool { return errTypes[i].count > errTypes[j].count })

	hasAny := false
	for _, et := range errTypes {
		if et.count > 0 {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return ""
	}

	b.WriteString("\nError type breakdown:\n")
	for _, et := range errTypes {
		if et.count > 0 {
			marker := ""
			if et.count == errTypes[0].count && errTypes[0].count > 0 {
				marker = " <-- dominant"
			}
			if totalErrors > 0 {
				pct := float64(et.count) / float64(totalErrors) * 100
				fmt.Fprintf(&b, "  %-20s %6s (%5.1f%%)%s\n", et.name+":", fmtCount(et.count), pct, marker)
			} else {
				fmt.Fprintf(&b, "  %-20s %6s%s\n", et.name+":", fmtCount(et.count), marker)
			}
		}
	}
	return b.String()
}

func (a *ExpvarDeepAnalyzer) forwarderSuggestion(errBlock string) string {
	if errBlock == "" {
		return "Check network connectivity, proxy settings, and firewall rules for Datadog endpoints."
	}

	tlsErrors := blockInt(errBlock, "TLSErrors")
	dnsErrors := blockInt(errBlock, "DNSErrors")
	connErrors := blockInt(errBlock, "ConnectionErrors")

	dominant := ""
	maxVal := int64(0)
	for _, pair := range []struct {
		name string
		val  int64
	}{
		{"tls", tlsErrors},
		{"dns", dnsErrors},
		{"conn", connErrors},
	} {
		if pair.val > maxVal {
			maxVal = pair.val
			dominant = pair.name
		}
	}

	switch dominant {
	case "tls":
		return "TLS errors are dominant. Common causes: SSL inspection by corporate proxy, expired intermediate CA, " +
			"or missing custom certificates in the agent's CA bundle. " +
			"Verify with: openssl s_client -connect intake.logs.datadoghq.com:443"
	case "dns":
		return "DNS resolution failures are dominant. Check /etc/resolv.conf, verify DNS servers are reachable, " +
			"and ensure *.datadoghq.com resolves correctly. Try: nslookup app.datadoghq.com"
	case "conn":
		return "TCP connection failures are dominant. The Datadog intake endpoints are unreachable. " +
			"Check firewall rules, proxy configuration, and network routing. " +
			"Required ports: 443 (HTTPS) for all endpoints."
	default:
		return "Check network connectivity, proxy settings, and firewall rules for Datadog endpoints."
	}
}

// ---------------------------------------------------------------------------
// Aggregator deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeAggregatorHealth(archive *extractor.FlareArchive) []types.Finding {
	data, err := archive.ReadFile("expvar/aggregator")
	if err != nil {
		return nil
	}
	content := string(data)
	var findings []types.Finding

	// Context cardinality analysis
	dogstatsdContexts := blockInt(content, "DogstatsdContexts")
	if dogstatsdContexts > 0 {
		sev := types.SeverityInfo
		if dogstatsdContexts > 50000 {
			sev = types.SeverityCritical
		} else if dogstatsdContexts > 10000 {
			sev = types.SeverityError
		} else if dogstatsdContexts > 5000 {
			sev = types.SeverityWarning
		}

		var desc strings.Builder
		fmt.Fprintf(&desc, "Active DogStatsD contexts: %s\n", fmtCount(dogstatsdContexts))

		// Context by metric type
		ctxByType := blockSection(content, "DogstatsdContextsByMtype")
		if len(ctxByType) > 0 {
			desc.WriteString("Breakdown by metric type:\n")
			type mtypeEntry struct {
				name  string
				count int64
			}
			var entries []mtypeEntry
			for k, v := range ctxByType {
				entries = append(entries, mtypeEntry{k, v})
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })

			for _, e := range entries {
				pct := float64(e.count) / float64(dogstatsdContexts) * 100
				fmt.Fprintf(&desc, "  %-15s %6s (%5.1f%%)\n", e.name+":", fmtCount(e.count), pct)
			}
		}

		if sev >= types.SeverityWarning {
			findings = append(findings, types.Finding{
				Severity:    sev,
				Category:    types.CategoryChecks,
				Title:       fmt.Sprintf("DogStatsD context cardinality: %s", fmtCount(dogstatsdContexts)),
				Description: desc.String(),
				Suggestion: "High context cardinality causes increased memory usage and custom metric costs. " +
					"Review custom metrics for unbounded tag values (user IDs, request IDs, timestamps). " +
					"See: https://docs.datadoghq.com/metrics/custom_metrics/",
				SourceFile: "expvar/aggregator",
			})
		} else {
			findings = append(findings, types.Finding{
				Severity:    sev,
				Category:    types.CategoryChecks,
				Title:       fmt.Sprintf("DogStatsD context cardinality: %s (healthy)", fmtCount(dogstatsdContexts)),
				Description: desc.String(),
				SourceFile:  "expvar/aggregator",
			})
		}
	}

	// Flush health
	seriesFlushed := blockInt(content, "SeriesFlushed")
	seriesFlushErrors := blockInt(content, "SeriesFlushErrors")
	sketchesFlushed := blockInt(content, "SketchesFlushed")
	sketchesFlushErrors := blockInt(content, "SketchesFlushErrors")
	eventsFlushed := blockInt(content, "EventsFlushed")
	eventsFlushErrors := blockInt(content, "EventsFlushErrors")
	scFlushed := blockInt(content, "ServiceCheckFlushed")
	scFlushErrors := blockInt(content, "ServiceCheckFlushErrors")

	totalFlushed := seriesFlushed + sketchesFlushed + eventsFlushed + scFlushed
	totalFlushErrors := seriesFlushErrors + sketchesFlushErrors + eventsFlushErrors + scFlushErrors

	if totalFlushErrors > 0 && totalFlushed > 0 {
		errRate := float64(totalFlushErrors) / float64(totalFlushed+totalFlushErrors) * 100
		var desc strings.Builder
		fmt.Fprintf(&desc, "Flush error rate: %.2f%% (%s errors / %s total)\n",
			errRate, fmtCount(totalFlushErrors), fmtCount(totalFlushed+totalFlushErrors))
		desc.WriteString("Breakdown:\n")
		if seriesFlushErrors > 0 {
			fmt.Fprintf(&desc, "  Series:         %s flushed, %s errors\n", fmtCount(seriesFlushed), fmtCount(seriesFlushErrors))
		}
		if sketchesFlushErrors > 0 {
			fmt.Fprintf(&desc, "  Sketches:       %s flushed, %s errors\n", fmtCount(sketchesFlushed), fmtCount(sketchesFlushErrors))
		}
		if eventsFlushErrors > 0 {
			fmt.Fprintf(&desc, "  Events:         %s flushed, %s errors\n", fmtCount(eventsFlushed), fmtCount(eventsFlushErrors))
		}
		if scFlushErrors > 0 {
			fmt.Fprintf(&desc, "  Service checks: %s flushed, %s errors\n", fmtCount(scFlushed), fmtCount(scFlushErrors))
		}

		sev := types.SeverityWarning
		if errRate > 10 {
			sev = types.SeverityError
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryHealth,
			Title:       fmt.Sprintf("Aggregator flush errors: %.1f%% failure rate", errRate),
			Description: desc.String(),
			Suggestion:  "Flush errors indicate the aggregator cannot send data to the forwarder. This is often caused by serialization issues or memory pressure.",
			SourceFile:  "expvar/aggregator",
		})
	}

	// DogStatsD sample processing
	dogstatsdSamples := blockInt(content, "DogstatsdMetricSample")
	checksSamples := blockInt(content, "ChecksMetricSample")
	if dogstatsdSamples > 0 || checksSamples > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryChecks,
			Title:       "Aggregator throughput",
			Description: fmt.Sprintf("Metric samples processed — DogStatsD: %s, Checks: %s", fmtCount(dogstatsdSamples), fmtCount(checksSamples)),
			SourceFile:  "expvar/aggregator",
		})
	}

	// Orchestrator metadata errors
	orchErrors := blockInt(content, "OrchestratorMetadataErrors")
	orchManifestErrors := blockInt(content, "OrchestratorManifestsErrors")
	if orchErrors > 0 || orchManifestErrors > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryContainer,
			Title:       "Orchestrator metadata errors",
			Description: fmt.Sprintf("Orchestrator metadata errors: %s, manifest errors: %s", fmtCount(orchErrors), fmtCount(orchManifestErrors)),
			Suggestion:  "Check cluster agent connectivity and Kubernetes API server access.",
			SourceFile:  "expvar/aggregator",
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// DogStatsD deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeDogstatsdHealth(archive *extractor.FlareArchive) []types.Finding {
	data, err := archive.ReadFile("expvar/dogstatsd")
	if err != nil {
		return nil
	}
	content := string(data)
	var findings []types.Finding

	metricPackets := blockInt(content, "MetricPackets")
	metricParseErrors := blockInt(content, "MetricParseErrors")
	eventPackets := blockInt(content, "EventPackets")
	eventParseErrors := blockInt(content, "EventParseErrors")
	scPackets := blockInt(content, "ServiceCheckPackets")
	scParseErrors := blockInt(content, "ServiceCheckParseErrors")
	unterminatedErrors := blockInt(content, "UnterminatedMetricErrors")

	totalPackets := metricPackets + eventPackets + scPackets
	totalParseErrors := metricParseErrors + eventParseErrors + scParseErrors + unterminatedErrors

	if totalPackets == 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryChecks,
			Title:       "DogStatsD: no packets received",
			Description: "DogStatsD has not received any metric packets. No custom metrics are being submitted via StatsD protocol.",
			Suggestion:  "If custom metrics are expected, verify that applications are sending to the correct DogStatsD port (default: 8125).",
			SourceFile:  "expvar/dogstatsd",
		})
		return findings
	}

	if totalParseErrors > 0 {
		parseErrRate := float64(totalParseErrors) / float64(totalPackets) * 100
		var desc strings.Builder
		fmt.Fprintf(&desc, "Parse error rate: %.2f%% (%s errors / %s packets)\n",
			parseErrRate, fmtCount(totalParseErrors), fmtCount(totalPackets))
		desc.WriteString("Breakdown:\n")
		fmt.Fprintf(&desc, "  Metric packets:  %s received, %s parse errors\n", fmtCount(metricPackets), fmtCount(metricParseErrors))
		fmt.Fprintf(&desc, "  Event packets:   %s received, %s parse errors\n", fmtCount(eventPackets), fmtCount(eventParseErrors))
		fmt.Fprintf(&desc, "  SC packets:      %s received, %s parse errors\n", fmtCount(scPackets), fmtCount(scParseErrors))
		if unterminatedErrors > 0 {
			fmt.Fprintf(&desc, "  Unterminated:    %s (missing newline at end of metric)\n", fmtCount(unterminatedErrors))
		}

		sev := types.SeverityWarning
		if parseErrRate > 5 {
			sev = types.SeverityError
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryChecks,
			Title:       fmt.Sprintf("DogStatsD parse errors: %.1f%% failure rate", parseErrRate),
			Description: desc.String(),
			Suggestion: "Parse errors indicate clients are sending malformed StatsD data. " +
				"Common causes: wrong protocol format, binary data on StatsD port, multi-metric payloads without proper newline separation. " +
				"Check application StatsD client library configuration.",
			SourceFile: "expvar/dogstatsd",
		})
	} else {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityInfo,
			Category:    types.CategoryChecks,
			Title:       fmt.Sprintf("DogStatsD healthy: %s packets processed", fmtCount(totalPackets)),
			Description: fmt.Sprintf("Metrics: %s, Events: %s, Service Checks: %s — no parse errors",
				fmtCount(metricPackets), fmtCount(eventPackets), fmtCount(scPackets)),
			SourceFile: "expvar/dogstatsd",
		})
	}

	// Check UDP listener stats
	udpData, err := archive.ReadFile("expvar/dogstatsd-udp")
	if err == nil {
		udpContent := string(udpData)
		udpPackets := blockInt(udpContent, "Packets")
		udpErrors := blockInt(udpContent, "PacketReadingErrors")
		udpBytes := blockInt(udpContent, "Bytes")
		if udpErrors > 0 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryChecks,
				Title:       fmt.Sprintf("DogStatsD UDP listener: %s read errors", fmtCount(udpErrors)),
				Description: fmt.Sprintf("UDP listener received %s packets (%s bytes) with %s read errors.", fmtCount(udpPackets), fmtBytes(udpBytes), fmtCount(udpErrors)),
				Suggestion:  "UDP read errors may indicate buffer overflow. Consider increasing net.core.rmem_max or using UDS transport instead.",
				SourceFile:  "expvar/dogstatsd-udp",
			})
		}
	}

	// Check UDS listener stats
	udsData, err := archive.ReadFile("expvar/dogstatsd-uds")
	if err == nil {
		udsContent := string(udsData)
		udsPackets := blockInt(udsContent, "Packets")
		udsErrors := blockInt(udsContent, "PacketReadingErrors")
		originErrors := blockInt(udsContent, "OriginDetectionErrors")
		if udsErrors > 0 || originErrors > 0 {
			findings = append(findings, types.Finding{
				Severity:    types.SeverityWarning,
				Category:    types.CategoryChecks,
				Title:       "DogStatsD UDS listener errors",
				Description: fmt.Sprintf("UDS listener: %s packets, %s read errors, %s origin detection errors.",
					fmtCount(udsPackets), fmtCount(udsErrors), fmtCount(originErrors)),
				Suggestion: "UDS read errors may indicate socket buffer issues. Origin detection errors mean the agent cannot determine which container sent the metric.",
				SourceFile: "expvar/dogstatsd-uds",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Runner/Collector deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeRunnerHealth(archive *extractor.FlareArchive) []types.Finding {
	// Try both "runner" and "collector" paths
	var content string
	var sourceFile string
	for _, path := range []string{"expvar/runner", "expvar/collector"} {
		data, err := archive.ReadFile(path)
		if err == nil {
			content = string(data)
			sourceFile = path
			break
		}
	}
	if content == "" {
		return nil
	}
	var findings []types.Finding

	totalRuns := blockInt(content, "Runs")
	totalErrors := blockInt(content, "Errors")
	totalWarnings := blockInt(content, "Warnings")
	runningCount := blockInt(content, "Running")

	if totalRuns > 0 {
		errRate := float64(totalErrors) / float64(totalRuns) * 100
		var desc strings.Builder
		fmt.Fprintf(&desc, "Total check runs: %s, errors: %s (%.2f%%), warnings: %s\n",
			fmtCount(totalRuns), fmtCount(totalErrors), errRate, fmtCount(totalWarnings))
		fmt.Fprintf(&desc, "Currently running: %s check(s)\n", fmtCount(runningCount))

		sev := types.SeverityInfo
		if errRate > 10 {
			sev = types.SeverityError
		} else if errRate > 1 {
			sev = types.SeverityWarning
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryChecks,
			Title:       fmt.Sprintf("Check runner: %.1f%% error rate across %s runs", errRate, fmtCount(totalRuns)),
			Description: desc.String(),
			SourceFile:  sourceFile,
		})
	}

	// Worker utilization
	workersBlock := extractBlock(content, "Workers")
	if workersBlock != "" {
		workerCount := blockInt(workersBlock, "Count")
		instancesBlock := extractBlock(workersBlock, "Instances")
		if instancesBlock != "" && workerCount > 0 {
			// Parse individual worker utilization
			utilRe := regexp.MustCompile(`Utilization:\s*([\d.]+)`)
			matches := utilRe.FindAllStringSubmatch(instancesBlock, -1)
			if len(matches) > 0 {
				var totalUtil float64
				var maxUtil float64
				for _, m := range matches {
					u, _ := strconv.ParseFloat(m[1], 64)
					totalUtil += u
					if u > maxUtil {
						maxUtil = u
					}
				}
				avgUtil := totalUtil / float64(len(matches))

				if maxUtil > 0.8 {
					findings = append(findings, types.Finding{
						Severity:    types.SeverityWarning,
						Category:    types.CategoryChecks,
						Title:       fmt.Sprintf("Check workers near saturation: max %.0f%% utilization", maxUtil*100),
						Description: fmt.Sprintf("%d workers, avg utilization %.1f%%, max %.1f%%. Check execution may be delayed.", workerCount, avgUtil*100, maxUtil*100),
						Suggestion:  "High worker utilization means checks are competing for execution slots. Consider increasing min_collection_interval for expensive checks.",
						SourceFile:  sourceFile,
					})
				}
			}
		}
	}

	// Per-check analysis from the Checks block
	checksBlock := extractBlock(content, "Checks")
	if checksBlock != "" {
		a.analyzePerCheckHealth(&findings, checksBlock, sourceFile)
	}

	return findings
}

func (a *ExpvarDeepAnalyzer) analyzePerCheckHealth(findings *[]types.Finding, checksBlock, sourceFile string) {
	// Parse individual check blocks
	// Format: checkname:\n  key: value\n  ...
	checkRe := regexp.MustCompile(`(?m)^  (\S+):\s*$`)
	checkNames := checkRe.FindAllStringSubmatch(checksBlock, -1)

	type checkHealth struct {
		name      string
		runs      int64
		errors    int64
		warnings  int64
		avgTime   int64
		lastTime  int64
		lastError string
	}

	var unhealthy []checkHealth
	var slow []checkHealth

	for _, cn := range checkNames {
		name := cn[1]
		checkBlock := extractBlock(checksBlock, name)
		if checkBlock == "" {
			continue
		}

		ch := checkHealth{
			name:     name,
			runs:     blockInt(checkBlock, "RunCount"),
			errors:   blockInt(checkBlock, "TotalErrors"),
			warnings: blockInt(checkBlock, "TotalWarnings"),
			avgTime:  blockInt(checkBlock, "AverageExecutionTime"),
			lastTime: blockInt(checkBlock, "LastExecutionTime"),
		}

		// Extract last error
		lastErrRe := regexp.MustCompile(`LastError:\s*"?([^"\n]+)"?`)
		if m := lastErrRe.FindStringSubmatch(checkBlock); len(m) > 1 && m[1] != "" {
			ch.lastError = m[1]
		}

		if ch.errors > 0 && ch.runs > 0 {
			unhealthy = append(unhealthy, ch)
		}

		// Slow check: average execution time > 15 seconds (15 billion nanoseconds)
		if ch.avgTime > 15_000_000_000 {
			slow = append(slow, ch)
		}
	}

	// Report unhealthy checks
	if len(unhealthy) > 0 {
		sort.Slice(unhealthy, func(i, j int) bool {
			ri := float64(unhealthy[i].errors) / float64(unhealthy[i].runs)
			rj := float64(unhealthy[j].errors) / float64(unhealthy[j].runs)
			return ri > rj
		})

		var desc strings.Builder
		desc.WriteString("Checks with errors (sorted by error rate):\n")
		for _, ch := range unhealthy {
			errRate := float64(ch.errors) / float64(ch.runs) * 100
			fmt.Fprintf(&desc, "  %-25s %5.1f%% error rate (%s errors / %s runs)\n",
				ch.name+":", errRate, fmtCount(ch.errors), fmtCount(ch.runs))
			if ch.lastError != "" {
				fmt.Fprintf(&desc, "    Last error: %s\n", truncate(ch.lastError, 120))
			}
		}

		*findings = append(*findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryChecks,
			Title:       fmt.Sprintf("%d check(s) with runtime errors", len(unhealthy)),
			Description: desc.String(),
			Suggestion:  "Review check configurations and connectivity to monitored services. High error rates indicate persistent issues.",
			SourceFile:  sourceFile,
		})
	}

	// Report slow checks
	if len(slow) > 0 {
		sort.Slice(slow, func(i, j int) bool { return slow[i].avgTime > slow[j].avgTime })

		var desc strings.Builder
		desc.WriteString("Checks with average execution >15s:\n")
		for _, ch := range slow {
			avgSec := float64(ch.avgTime) / 1_000_000_000
			fmt.Fprintf(&desc, "  %-25s avg %.1fs\n", ch.name+":", avgSec)
		}

		*findings = append(*findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryChecks,
			Title:       fmt.Sprintf("%d slow check(s) detected (>15s avg execution)", len(slow)),
			Description: desc.String(),
			Suggestion:  "Slow checks can delay other checks and consume worker slots. Consider increasing min_collection_interval or optimizing the check query/endpoint.",
			SourceFile:  sourceFile,
		})
	}
}

// ---------------------------------------------------------------------------
// Logs agent deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeLogsAgentHealth(archive *extractor.FlareArchive) []types.Finding {
	data, err := archive.ReadFile("expvar/logs-agent")
	if err != nil {
		return nil
	}
	content := string(data)
	var findings []types.Finding

	decoded := blockInt(content, "LogsDecoded")
	processed := blockInt(content, "LogsProcessed")
	sent := blockInt(content, "LogsSent")
	truncated := blockInt(content, "LogsTruncated")
	destErrors := blockInt(content, "DestinationErrors")
	bytesSent := blockInt(content, "BytesSent")
	encodedBytesSent := blockInt(content, "EncodedBytesSent")
	bytesMissed := blockInt(content, "BytesMissed")
	retryCount := blockInt(content, "RetryCount")
	senderLatency := blockInt(content, "SenderLatency")

	if decoded == 0 && sent == 0 {
		return nil
	}

	// Pipeline health
	var desc strings.Builder
	desc.WriteString("Log pipeline metrics:\n")
	fmt.Fprintf(&desc, "  Decoded:    %s\n", fmtCount(decoded))
	fmt.Fprintf(&desc, "  Processed:  %s\n", fmtCount(processed))
	fmt.Fprintf(&desc, "  Sent:       %s\n", fmtCount(sent))

	if decoded > 0 {
		sendRate := float64(sent) / float64(decoded) * 100
		fmt.Fprintf(&desc, "  Send rate:  %.1f%%\n", sendRate)
	}

	if truncated > 0 {
		truncRate := float64(0)
		if decoded > 0 {
			truncRate = float64(truncated) / float64(decoded) * 100
		}
		fmt.Fprintf(&desc, "  Truncated:  %s (%.1f%%)\n", fmtCount(truncated), truncRate)
	}

	if bytesSent > 0 {
		fmt.Fprintf(&desc, "  Bytes sent: %s", fmtBytes(bytesSent))
		if encodedBytesSent > 0 && bytesSent > 0 {
			compRatio := float64(encodedBytesSent) / float64(bytesSent) * 100
			fmt.Fprintf(&desc, " (compressed to %.0f%%)", compRatio)
		}
		desc.WriteString("\n")
	}

	if senderLatency > 0 {
		fmt.Fprintf(&desc, "  Sender latency: %dms\n", senderLatency)
	}

	// Determine severity
	sev := types.SeverityInfo
	suggestion := ""

	if destErrors > 0 {
		sev = types.SeverityError
		fmt.Fprintf(&desc, "\nDestination errors: %s\n", fmtCount(destErrors))
		suggestion = "Destination errors indicate the logs agent cannot reach the Datadog logs intake. Check connectivity and API key."
	}

	if bytesMissed > 0 {
		if sev < types.SeverityWarning {
			sev = types.SeverityWarning
		}
		fmt.Fprintf(&desc, "Bytes missed (data loss): %s\n", fmtBytes(bytesMissed))
		suggestion += " Bytes missed indicates log data was lost due to file rotation or truncation before the agent could read it."
	}

	if retryCount > 0 {
		if sev < types.SeverityWarning {
			sev = types.SeverityWarning
		}
		fmt.Fprintf(&desc, "Retry attempts: %s\n", fmtCount(retryCount))
	}

	if truncated > 0 && decoded > 0 {
		truncRate := float64(truncated) / float64(decoded) * 100
		if truncRate > 5 {
			if sev < types.SeverityWarning {
				sev = types.SeverityWarning
			}
			if suggestion != "" {
				suggestion += " "
			}
			suggestion += "High truncation rate — log lines may exceed max message size. Consider adjusting logs_config.max_message_size_bytes."
		}
	}

	if senderLatency > 1000 {
		if sev < types.SeverityWarning {
			sev = types.SeverityWarning
		}
		if suggestion != "" {
			suggestion += " "
		}
		suggestion += fmt.Sprintf("High sender latency (%dms) may indicate network issues to the logs intake endpoint.", senderLatency)
	}

	title := "Logs agent pipeline health"
	if sev >= types.SeverityError {
		title = "Logs agent pipeline errors"
	}

	// Dropped logs per destination
	droppedByDest := blockSection(content, "DestinationLogsDropped")
	if len(droppedByDest) > 0 {
		hasDrops := false
		for _, v := range droppedByDest {
			if v > 0 {
				hasDrops = true
				break
			}
		}
		if hasDrops {
			sev = types.SeverityError
			desc.WriteString("\nLogs dropped by destination:\n")
			for dest, count := range droppedByDest {
				if count > 0 {
					fmt.Fprintf(&desc, "  %s: %s\n", dest, fmtCount(count))
				}
			}
		}
	}

	findings = append(findings, types.Finding{
		Severity:    sev,
		Category:    types.CategoryLogs,
		Title:       title,
		Description: desc.String(),
		Suggestion:  suggestion,
		SourceFile:  "expvar/logs-agent",
	})

	return findings
}

// ---------------------------------------------------------------------------
// Memory and runtime deep analysis
// ---------------------------------------------------------------------------

func (a *ExpvarDeepAnalyzer) analyzeMemoryAndRuntime(archive *extractor.FlareArchive) []types.Finding {
	data, err := archive.ReadFile("expvar/agent")
	if err != nil {
		return nil
	}
	content := string(data)
	var findings []types.Finding

	// Memory stats (from Go runtime memstats)
	memBlock := extractBlock(content, "memstats")
	if memBlock == "" {
		// Try flat structure
		memBlock = content
	}

	alloc := blockInt(memBlock, "Alloc")
	totalAlloc := blockInt(memBlock, "TotalAlloc")
	sys := blockInt(memBlock, "Sys")
	heapAlloc := blockInt(memBlock, "HeapAlloc")
	heapInuse := blockInt(memBlock, "HeapInuse")
	heapIdle := blockInt(memBlock, "HeapIdle")
	heapReleased := blockInt(memBlock, "HeapReleased")
	numGC := blockInt(memBlock, "NumGC")
	pauseTotalNs := blockInt(memBlock, "PauseTotalNs")
	numGoroutine := blockInt(content, "goroutines")

	if sys > 0 || alloc > 0 {
		var desc strings.Builder
		desc.WriteString("Go runtime memory statistics:\n")
		if alloc > 0 {
			fmt.Fprintf(&desc, "  Current allocation:  %s\n", fmtBytes(alloc))
		}
		if heapAlloc > 0 {
			fmt.Fprintf(&desc, "  Heap in use:         %s\n", fmtBytes(heapInuse))
			fmt.Fprintf(&desc, "  Heap idle:           %s\n", fmtBytes(heapIdle))
			if heapReleased > 0 {
				fmt.Fprintf(&desc, "  Heap released to OS: %s\n", fmtBytes(heapReleased))
			}
		}
		if sys > 0 {
			fmt.Fprintf(&desc, "  Total from OS:       %s\n", fmtBytes(sys))
		}
		if totalAlloc > 0 {
			fmt.Fprintf(&desc, "  Cumulative alloc:    %s\n", fmtBytes(totalAlloc))
		}
		if numGC > 0 {
			fmt.Fprintf(&desc, "  GC cycles:           %s\n", fmtCount(numGC))
			if pauseTotalNs > 0 {
				pauseMs := float64(pauseTotalNs) / 1_000_000
				avgPauseMs := pauseMs / float64(numGC)
				fmt.Fprintf(&desc, "  Total GC pause:      %.1fms (avg %.2fms/cycle)\n", pauseMs, avgPauseMs)
			}
		}
		if numGoroutine > 0 {
			fmt.Fprintf(&desc, "  Goroutines:          %s\n", fmtCount(numGoroutine))
		}

		sev := types.SeverityInfo
		suggestion := ""

		// High memory usage
		if sys > 2*1024*1024*1024 { // > 2GB
			sev = types.SeverityError
			suggestion = "Agent is using over 2GB of memory. Check for high-cardinality metrics, too many checks, or memory leaks. Consider setting a memory limit (e.g., cgroup limits in containers)."
		} else if sys > 1*1024*1024*1024 { // > 1GB
			sev = types.SeverityWarning
			suggestion = "Agent memory usage is elevated. Review enabled checks and DogStatsD context cardinality."
		}

		// GC pressure
		if numGC > 0 && pauseTotalNs > 0 {
			avgPauseMs := float64(pauseTotalNs) / 1_000_000 / float64(numGC)
			if avgPauseMs > 10 {
				if sev < types.SeverityWarning {
					sev = types.SeverityWarning
				}
				if suggestion != "" {
					suggestion += " "
				}
				suggestion += fmt.Sprintf("High GC pause time (avg %.1fms) indicates memory pressure. The agent may experience latency spikes during GC.", avgPauseMs)
			}
		}

		// Heap fragmentation
		if heapInuse > 0 && heapIdle > 0 {
			idleRatio := float64(heapIdle) / float64(heapInuse+heapIdle) * 100
			if idleRatio > 70 {
				desc.WriteString(fmt.Sprintf("\n  Heap utilization:    %.0f%% idle — possible fragmentation\n", idleRatio))
			}
		}

		findings = append(findings, types.Finding{
			Severity:    sev,
			Category:    types.CategoryResources,
			Title:       fmt.Sprintf("Agent memory: %s allocated, %s from OS", fmtBytes(alloc), fmtBytes(sys)),
			Description: desc.String(),
			Suggestion:  suggestion,
			SourceFile:  "expvar/agent",
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helper functions for expvar parsing
// ---------------------------------------------------------------------------

// extractBlock extracts a YAML block starting at the given key,
// returning all indented content below it. Handles both YAML and JSON-like formats.
func extractBlock(content, key string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inBlock := false
	blockIndent := -1

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inBlock {
			// Match key with optional quotes: key:, "key":
			stripped := strings.TrimSpace(strings.Trim(trimmed, `"`))
			if strings.HasPrefix(stripped, key+":") || strings.HasPrefix(stripped, key+" :") {
				inBlock = true
				indent := len(line) - len(strings.TrimLeft(line, " \t"))
				blockIndent = indent

				// Check for inline value (key: value on same line)
				afterColon := ""
				idx := strings.Index(stripped, ":")
				if idx >= 0 {
					afterColon = strings.TrimSpace(stripped[idx+1:])
				}
				if afterColon != "" && afterColon != "{}" && afterColon != "[]" {
					return afterColon
				}
				continue
			}
		} else {
			if trimmed == "" {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if indent <= blockIndent {
				break
			}
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// blockInt extracts an integer value for a key from a YAML/JSON block.
func blockInt(block, key string) int64 {
	// Match: key: 123 or "key": 123 (with flexible spacing)
	re := regexp.MustCompile(`(?m)(?:^|\s)"?` + regexp.QuoteMeta(key) + `"?\s*:\s*(\d+)`)
	if m := re.FindStringSubmatch(block); len(m) > 1 {
		val, _ := strconv.ParseInt(m[1], 10, 64)
		return val
	}
	return 0
}

// blockSection extracts all key-value pairs from a named subsection.
func blockSection(content, key string) map[string]int64 {
	result := make(map[string]int64)

	block := extractBlock(content, key)
	if block == "" {
		return result
	}

	// Parse each line in the block as key: value
	lines := strings.Split(block, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.Trim(strings.TrimSpace(parts[0]), `"`)
		v := strings.TrimSpace(parts[1])
		if val, err := strconv.ParseInt(v, 10, 64); err == nil {
			result[k] = val
		}
	}
	return result
}

// fmtCount formats a number with thousand separators for readability.
func fmtCount(n int64) string {
	if n < 0 {
		return "-" + fmtCount(-n)
	}
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}

	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// fmtBytes formats byte counts into human-readable form.
func fmtBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// httpCodeHint returns a human hint for HTTP status codes.
func httpCodeHint(code string) string {
	switch {
	case code == "400":
		return " (bad request — payload format issue)"
	case code == "401":
		return " (unauthorized — API key issue)"
	case code == "403":
		return " (forbidden — API key invalid or lacks permissions)"
	case code == "404":
		return " (not found — wrong endpoint URL)"
	case code == "408":
		return " (request timeout)"
	case code == "413":
		return " (payload too large)"
	case code == "429":
		return " (rate limited by Datadog)"
	case strings.HasPrefix(code, "5"):
		return " (Datadog server error — typically transient)"
	default:
		return ""
	}
}
