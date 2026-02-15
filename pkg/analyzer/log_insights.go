package analyzer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/extractor"
	"github.com/ArmentaRoberto/datadog-agent-flare-tool/pkg/types"
)

// LogInsightAnalyzer performs deep log analysis: temporal patterns, error
// classification, cross-component correlation, stack trace extraction,
// and root cause inference. This goes far beyond counting errors — it
// answers "what happened, when, and why?"
type LogInsightAnalyzer struct{}

func (a *LogInsightAnalyzer) Name() string { return "Log Insight Analyzer" }

// logEntry is a parsed log line with structured fields.
type logEntry struct {
	timestamp time.Time
	component string
	level     string
	message   string
	source    string // source log file
	raw       string // original line
}

// errorClass categorizes an error by its root cause domain.
type errorClass string

const (
	errClassNetwork    errorClass = "Network"
	errClassPermission errorClass = "Permission"
	errClassConfig     errorClass = "Configuration"
	errClassResource   errorClass = "Resource"
	errClassCrash      errorClass = "Crash"
	errClassData       errorClass = "Data"
	errClassTimeout    errorClass = "Timeout"
	errClassTLS        errorClass = "TLS/Certificate"
	errClassUnknown    errorClass = "Other"
)

// errorClassPattern maps regex patterns to error classes.
var errorClassPatterns = []struct {
	class   errorClass
	pattern *regexp.Regexp
}{
	{errClassCrash, regexp.MustCompile(`(?i)(panic|fatal|signal \d+|SIGSEGV|SIGABRT|stack trace|goroutine \d+)`)},
	{errClassResource, regexp.MustCompile(`(?i)(out of memory|OOM|cannot allocate|too many open files|no space left|disk full|ulimit|ENOMEM|ENOSPC|EMFILE)`)},
	{errClassTLS, regexp.MustCompile(`(?i)(certificate|x509|TLS|SSL|handshake|CA bundle|cert pool|tls:)`)},
	{errClassPermission, regexp.MustCompile(`(?i)(permission denied|access denied|forbidden|EACCES|EPERM|selinux|apparmor|unauthorized)`)},
	{errClassTimeout, regexp.MustCompile(`(?i)(timeout|timed out|deadline exceeded|context deadline|i/o timeout|read tcp .+ i/o timeout)`)},
	{errClassNetwork, regexp.MustCompile(`(?i)(connection refused|connection reset|no route|unreachable|ECONNREFUSED|ECONNRESET|ENETUNREACH|dial tcp|DNS|lookup .+ on|no such host|broken pipe)`)},
	{errClassConfig, regexp.MustCompile(`(?i)(invalid config|misconfigur|yaml:|json:|unmarshal|no such file|not found|ENOENT|missing required|unknown key|invalid value)`)},
	{errClassData, regexp.MustCompile(`(?i)(parse error|invalid format|unexpected token|malformed|encoding|decode error|corrupt)`)},
}

// timestamp formats used by the Datadog Agent.
var timestampFormats = []string{
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05",
}

// timestampRe extracts the timestamp prefix from a log line.
var timestampRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\|]*)`)

// knownLevels is used for positional log level extraction.
var knownLevels = map[string]bool{
	"TRACE": true, "DEBUG": true, "INFO": true,
	"WARN": true, "WARNING": true,
	"ERROR": true, "ERRO": true,
	"CRITICAL": true, "FATAL": true,
}

func isKnownLevel(s string) bool {
	return knownLevels[strings.ToUpper(s)]
}

func (a *LogInsightAnalyzer) Analyze(archive *extractor.FlareArchive) []types.Finding {
	var findings []types.Finding

	// Parse all log files into structured entries
	allEntries := make(map[string][]logEntry)
	var allErrors []logEntry

	for _, logFile := range logFiles {
		data, err := archive.ReadFile(logFile)
		if err != nil {
			continue
		}

		entries := parseLogEntries(string(data), logFile)
		if len(entries) == 0 {
			continue
		}
		allEntries[logFile] = entries

		for _, e := range entries {
			if isErrorLevel(e.level) {
				allErrors = append(allErrors, e)
			}
		}
	}

	if len(allErrors) == 0 {
		return nil // The basic LogAnalyzer already reports "no errors"
	}

	// 1. Temporal analysis — detect error spikes and trends
	findings = append(findings, a.analyzeTemporalPatterns(allErrors)...)

	// 2. Error classification — categorize errors by root cause domain
	findings = append(findings, a.classifyAndSummarize(allErrors)...)

	// 3. Cross-component correlation — find systemic issues
	findings = append(findings, a.analyzeComponentCorrelation(allEntries)...)

	// 4. Stack trace / crash extraction
	findings = append(findings, a.extractCrashInfo(allEntries)...)

	// 5. Root cause inference — synthesize all signals
	findings = append(findings, a.inferRootCauses(allErrors)...)

	return findings
}

// ---------------------------------------------------------------------------
// Log parsing
// ---------------------------------------------------------------------------

func parseLogEntries(content, source string) []logEntry {
	lines := strings.Split(content, "\n")
	var entries []logEntry

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		e := logEntry{
			raw:    line,
			source: source,
		}

		// Parse using pipe-delimited positions:
		// Format: timestamp | COMPONENT | LEVEL | (source) | message
		// Field 0: timestamp, Field 1: component, Field 2: level, Field 3+: rest
		parts := strings.SplitN(line, "|", 5)

		// Extract timestamp from field 0
		if len(parts) >= 1 {
			ts := strings.TrimSpace(parts[0])
			if ts != "" {
				e.timestamp = parseTimestamp(ts)
			}
		}

		// Extract component from field 1
		if len(parts) >= 2 {
			e.component = strings.TrimSpace(parts[1])
		}

		// Extract level from field 2 (the correct position)
		if len(parts) >= 3 {
			levelStr := strings.TrimSpace(parts[2])
			if isKnownLevel(levelStr) {
				e.level = normalizeLevel(levelStr)
			}
		}

		// Extract message from remaining fields
		if len(parts) >= 5 {
			e.message = strings.TrimSpace(parts[4])
		} else if len(parts) >= 4 {
			e.message = strings.TrimSpace(parts[3])
		} else {
			e.message = line
		}

		entries = append(entries, e)
	}

	return entries
}

func parseTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, fmt := range timestampFormats {
		if t, err := time.Parse(fmt, s); err == nil {
			return t
		}
	}
	// Try ISO format
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func normalizeLevel(level string) string {
	switch strings.ToUpper(level) {
	case "ERRO":
		return "ERROR"
	case "WARNING":
		return "WARN"
	default:
		return strings.ToUpper(level)
	}
}

func isErrorLevel(level string) bool {
	switch level {
	case "ERROR", "CRITICAL", "FATAL":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Temporal analysis — detect error spikes and trends
// ---------------------------------------------------------------------------

func (a *LogInsightAnalyzer) analyzeTemporalPatterns(errors []logEntry) []types.Finding {
	var findings []types.Finding

	// Filter entries with valid timestamps
	var timed []logEntry
	for _, e := range errors {
		if !e.timestamp.IsZero() {
			timed = append(timed, e)
		}
	}
	if len(timed) < 5 {
		return nil // Not enough data for temporal analysis
	}

	// Sort by timestamp
	sort.Slice(timed, func(i, j int) bool { return timed[i].timestamp.Before(timed[j].timestamp) })

	earliest := timed[0].timestamp
	latest := timed[len(timed)-1].timestamp
	duration := latest.Sub(earliest)

	if duration < 5*time.Minute {
		return nil // Too short a window for meaningful temporal analysis
	}

	// Bucket errors into 5-minute windows
	bucketSize := 5 * time.Minute
	type bucket struct {
		start time.Time
		count int
		msgs  map[string]int
	}

	buckets := make(map[int64]*bucket)
	for _, e := range timed {
		key := e.timestamp.Truncate(bucketSize).Unix()
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				start: e.timestamp.Truncate(bucketSize),
				msgs:  make(map[string]int),
			}
			buckets[key] = b
		}
		b.count++
		// Normalize message for deduplication
		shortMsg := normalizeErrorMsg(e.message)
		b.msgs[shortMsg]++
	}

	// Calculate average error rate
	totalBuckets := int(duration/bucketSize) + 1
	if totalBuckets < 1 {
		totalBuckets = 1
	}
	avgRate := float64(len(timed)) / float64(totalBuckets)

	// Find spike buckets (> 3x average, minimum 10 errors)
	spikeThreshold := avgRate * 3
	if spikeThreshold < 10 {
		spikeThreshold = 10
	}

	var spikes []bucket
	for _, b := range buckets {
		if float64(b.count) > spikeThreshold {
			spikes = append(spikes, *b)
		}
	}

	if len(spikes) > 0 {
		sort.Slice(spikes, func(i, j int) bool { return spikes[i].count > spikes[j].count })

		var desc strings.Builder
		fmt.Fprintf(&desc, "Normal error rate: ~%.0f errors per 5min\n", avgRate)
		fmt.Fprintf(&desc, "Detected %d spike period(s) (>%.0f errors/5min):\n\n", len(spikes), spikeThreshold)

		showSpikes := len(spikes)
		if showSpikes > 3 {
			showSpikes = 3
		}

		for i := 0; i < showSpikes; i++ {
			s := spikes[i]
			multiplier := float64(s.count) / avgRate
			fmt.Fprintf(&desc, "  %s — %d errors (%.0fx normal)\n",
				s.start.Format("2006-01-02 15:04"), s.count, multiplier)

			// Top errors during spike
			type msgCount struct {
				msg   string
				count int
			}
			var topMsgs []msgCount
			for m, c := range s.msgs {
				topMsgs = append(topMsgs, msgCount{m, c})
			}
			sort.Slice(topMsgs, func(a, b int) bool { return topMsgs[a].count > topMsgs[b].count })

			showMsgs := len(topMsgs)
			if showMsgs > 3 {
				showMsgs = 3
			}
			for j := 0; j < showMsgs; j++ {
				fmt.Fprintf(&desc, "    (%dx) %s\n", topMsgs[j].count, truncate(topMsgs[j].msg, 100))
			}
			desc.WriteString("\n")
		}

		findings = append(findings, types.Finding{
			Severity:    types.SeverityError,
			Category:    types.CategoryLogs,
			Title:       fmt.Sprintf("Error spike detected: %d spike period(s)", len(spikes)),
			Description: desc.String(),
			Suggestion:  "Error spikes indicate a sudden onset of issues. Correlate the spike timestamps with infrastructure changes (deployments, config changes, network events).",
			SourceFile:  "logs/",
		})
	}

	// Trend analysis: are errors increasing over time?
	// Split the time range into two halves and compare
	midpoint := earliest.Add(duration / 2)
	firstHalfCount := 0
	secondHalfCount := 0
	for _, e := range timed {
		if e.timestamp.Before(midpoint) {
			firstHalfCount++
		} else {
			secondHalfCount++
		}
	}

	if firstHalfCount > 0 && secondHalfCount > 0 {
		ratio := float64(secondHalfCount) / float64(firstHalfCount)
		if ratio > 2.0 {
			findings = append(findings, types.Finding{
				Severity: types.SeverityWarning,
				Category: types.CategoryLogs,
				Title:    "Error rate increasing over time",
				Description: fmt.Sprintf("First half: %d errors, second half: %d errors (%.1fx increase).\n"+
					"Errors are trending upward, suggesting a degrading condition.",
					firstHalfCount, secondHalfCount, ratio),
				Suggestion: "An increasing error trend suggests a worsening condition (e.g., resource exhaustion, growing backlog, connection pool depletion). Investigate root cause before it leads to failure.",
				SourceFile: "logs/",
			})
		} else if ratio < 0.3 && firstHalfCount > 20 {
			findings = append(findings, types.Finding{
				Severity: types.SeverityInfo,
				Category: types.CategoryLogs,
				Title:    "Error rate decreasing — possible recovery",
				Description: fmt.Sprintf("First half: %d errors, second half: %d errors.\n"+
					"Errors are trending downward, suggesting the issue may be resolving.",
					firstHalfCount, secondHalfCount),
				SourceFile: "logs/",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Error classification — categorize by root cause domain
// ---------------------------------------------------------------------------

func (a *LogInsightAnalyzer) classifyAndSummarize(errors []logEntry) []types.Finding {
	var findings []types.Finding

	classCounts := make(map[errorClass]int)
	classExamples := make(map[errorClass]map[string]int)

	for _, e := range errors {
		cls := classifyError(e.message)
		classCounts[cls]++
		if classExamples[cls] == nil {
			classExamples[cls] = make(map[string]int)
		}
		shortMsg := normalizeErrorMsg(e.message)
		classExamples[cls][shortMsg]++
	}

	if len(classCounts) == 0 {
		return nil
	}

	// Sort classes by count
	type classEntry struct {
		class errorClass
		count int
	}
	var sorted []classEntry
	for cls, cnt := range classCounts {
		sorted = append(sorted, classEntry{cls, cnt})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })

	var desc strings.Builder
	desc.WriteString("Error classification across all log files:\n\n")

	for _, ce := range sorted {
		pct := float64(ce.count) / float64(len(errors)) * 100
		fmt.Fprintf(&desc, "  %-18s %5d errors (%5.1f%%)", ce.class+":", ce.count, pct)
		if ce.class == sorted[0].class && len(sorted) > 1 {
			desc.WriteString(" <-- dominant")
		}
		desc.WriteString("\n")

		// Top examples for this class
		examples := classExamples[ce.class]
		type exEntry struct {
			msg   string
			count int
		}
		var exSorted []exEntry
		for msg, cnt := range examples {
			exSorted = append(exSorted, exEntry{msg, cnt})
		}
		sort.Slice(exSorted, func(i, j int) bool { return exSorted[i].count > exSorted[j].count })

		showEx := len(exSorted)
		if showEx > 2 {
			showEx = 2
		}
		for i := 0; i < showEx; i++ {
			fmt.Fprintf(&desc, "    (%dx) %s\n", exSorted[i].count, truncate(exSorted[i].msg, 100))
		}
		desc.WriteString("\n")
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityError,
		Category:    types.CategoryLogs,
		Title:       fmt.Sprintf("Error classification: %d errors in %d categories", len(errors), len(classCounts)),
		Description: desc.String(),
		Suggestion:  errorClassSuggestion(sorted[0].class),
		SourceFile:  "logs/",
	})

	return findings
}

func classifyError(message string) errorClass {
	for _, p := range errorClassPatterns {
		if p.pattern.MatchString(message) {
			return p.class
		}
	}
	return errClassUnknown
}

func errorClassSuggestion(dominant errorClass) string {
	switch dominant {
	case errClassNetwork:
		return "Network errors are dominant. Check: firewall rules, proxy configuration, DNS resolution, and that target services are running and accessible."
	case errClassPermission:
		return "Permission errors are dominant. Check: dd-agent user permissions, file ownership, SELinux/AppArmor policies, and container security contexts."
	case errClassConfig:
		return "Configuration errors are dominant. Check: YAML syntax in datadog.yaml and conf.d/ files, ensure all referenced files/paths exist."
	case errClassResource:
		return "Resource exhaustion is dominant. Check: memory limits (cgroup/container), ulimits (nofile), disk space, and consider reducing check frequency or cardinality."
	case errClassCrash:
		return "Crash/panic errors detected. This is likely an agent bug. Collect the full stack trace and consider upgrading the agent or filing a bug report."
	case errClassTLS:
		return "TLS/certificate errors are dominant. Check: certificate validity (openssl s_client), CA bundle configuration, proxy SSL inspection, and skip_ssl_validation settings."
	case errClassTimeout:
		return "Timeout errors are dominant. Check: network latency, target service health, and consider increasing timeout configuration values."
	case errClassData:
		return "Data parsing errors are dominant. Check: data formats being sent to the agent, encoding settings, and integration configurations."
	default:
		return "Review the top error messages for patterns and investigate the most frequent ones first."
	}
}

// ---------------------------------------------------------------------------
// Cross-component correlation
// ---------------------------------------------------------------------------

func (a *LogInsightAnalyzer) analyzeComponentCorrelation(allEntries map[string][]logEntry) []types.Finding {
	var findings []types.Finding

	// Collect error entries with timestamps per component
	type componentErrors struct {
		name   string
		errors []logEntry
	}

	var components []componentErrors
	for source, entries := range allEntries {
		var errs []logEntry
		for _, e := range entries {
			if isErrorLevel(e.level) && !e.timestamp.IsZero() {
				errs = append(errs, e)
			}
		}
		if len(errs) > 0 {
			components = append(components, componentErrors{
				name:   logFileToComponent(source),
				errors: errs,
			})
		}
	}

	if len(components) < 2 {
		return nil // Need at least 2 components for correlation
	}

	// Find overlapping error windows across components
	// For each pair of components, check if errors co-occur within 2-minute windows
	windowSize := 2 * time.Minute

	type correlation struct {
		comp1, comp2 string
		window       time.Time
		count1       int
		count2       int
	}

	var correlations []correlation
	seen := make(map[string]bool)

	for i := 0; i < len(components); i++ {
		for j := i + 1; j < len(components); j++ {
			c1 := components[i]
			c2 := components[j]

			// Build time buckets for component 1
			buckets1 := make(map[int64]int)
			for _, e := range c1.errors {
				key := e.timestamp.Truncate(windowSize).Unix()
				buckets1[key]++
			}

			// Check for co-occurring errors in component 2
			for _, e := range c2.errors {
				key := e.timestamp.Truncate(windowSize).Unix()
				if count1, ok := buckets1[key]; ok && count1 > 0 {
					corrKey := fmt.Sprintf("%s-%s-%d", c1.name, c2.name, key)
					if !seen[corrKey] {
						seen[corrKey] = true
						// Count component 2 errors in same bucket
						count2 := 0
						for _, e2 := range c2.errors {
							if e2.timestamp.Truncate(windowSize).Unix() == key {
								count2++
							}
						}
						correlations = append(correlations, correlation{
							comp1:  c1.name,
							comp2:  c2.name,
							window: time.Unix(key, 0),
							count1: count1,
							count2: count2,
						})
					}
				}
			}
		}
	}

	if len(correlations) == 0 {
		return nil
	}

	// Group by component pairs
	type pairCorr struct {
		comp1, comp2 string
		windows      int
		totalErrors  int
	}

	pairs := make(map[string]*pairCorr)
	for _, c := range correlations {
		key := c.comp1 + "+" + c.comp2
		p, ok := pairs[key]
		if !ok {
			p = &pairCorr{comp1: c.comp1, comp2: c.comp2}
			pairs[key] = p
		}
		p.windows++
		p.totalErrors += c.count1 + c.count2
	}

	var sortedPairs []*pairCorr
	for _, p := range pairs {
		sortedPairs = append(sortedPairs, p)
	}
	sort.Slice(sortedPairs, func(i, j int) bool { return sortedPairs[i].totalErrors > sortedPairs[j].totalErrors })

	var desc strings.Builder
	desc.WriteString("Components experiencing errors at the same time (within 2-min windows):\n\n")

	showPairs := len(sortedPairs)
	if showPairs > 5 {
		showPairs = 5
	}

	for i := 0; i < showPairs; i++ {
		p := sortedPairs[i]
		fmt.Fprintf(&desc, "  %s + %s: %d concurrent error window(s), %d total errors\n",
			p.comp1, p.comp2, p.windows, p.totalErrors)
	}

	if len(sortedPairs) > 0 && sortedPairs[0].windows > 3 {
		findings = append(findings, types.Finding{
			Severity: types.SeverityError,
			Category: types.CategoryHealth,
			Title:    "Cross-component error correlation detected",
			Description: desc.String() + "\nMultiple agent components are failing simultaneously, " +
				"indicating a systemic issue rather than isolated component failures.",
			Suggestion: "Concurrent errors across components often point to: network outage, " +
				"host resource exhaustion (CPU/memory/disk), or a shared dependency failure. " +
				"Check infrastructure metrics around the error timestamps.",
			SourceFile: "logs/",
		})
	} else if len(sortedPairs) > 0 {
		findings = append(findings, types.Finding{
			Severity:    types.SeverityWarning,
			Category:    types.CategoryHealth,
			Title:       "Cross-component error correlation",
			Description: desc.String(),
			SourceFile:  "logs/",
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Crash / stack trace extraction
// ---------------------------------------------------------------------------

func (a *LogInsightAnalyzer) extractCrashInfo(allEntries map[string][]logEntry) []types.Finding {
	var findings []types.Finding

	for source, entries := range allEntries {
		component := logFileToComponent(source)

		// Look for panic sequences
		var panicLines []string
		inPanic := false

		for _, e := range entries {
			if strings.Contains(e.raw, "panic:") || strings.Contains(e.raw, "runtime error:") {
				inPanic = true
				panicLines = nil
			}

			if inPanic {
				panicLines = append(panicLines, e.raw)
				// Collect up to 20 lines of stack trace
				if len(panicLines) > 20 {
					break
				}
			}

			// End of stack trace (empty line or new log entry with timestamp)
			if inPanic && len(panicLines) > 3 {
				if e.raw == "" || (timestampRe.MatchString(e.raw) && !strings.Contains(e.raw, "goroutine")) {
					inPanic = false

					// Extract the panic message and top stack frame
					panicMsg := ""
					topFrame := ""
					for _, pl := range panicLines {
						if strings.Contains(pl, "panic:") || strings.Contains(pl, "runtime error:") {
							panicMsg = strings.TrimSpace(pl)
						}
						// Look for the first non-runtime stack frame
						if topFrame == "" && strings.Contains(pl, ".go:") && !strings.Contains(pl, "runtime/") {
							topFrame = strings.TrimSpace(pl)
						}
					}

					if panicMsg != "" {
						var desc strings.Builder
						fmt.Fprintf(&desc, "Crash in %s:\n", component)
						fmt.Fprintf(&desc, "  %s\n", truncate(panicMsg, 150))
						if topFrame != "" {
							fmt.Fprintf(&desc, "  Top frame: %s\n", truncate(topFrame, 150))
						}
						fmt.Fprintf(&desc, "\nStack trace (%d lines captured):\n", len(panicLines))
						showLines := len(panicLines)
						if showLines > 10 {
							showLines = 10
						}
						for k := 0; k < showLines; k++ {
							fmt.Fprintf(&desc, "  %s\n", truncate(panicLines[k], 120))
						}
						if len(panicLines) > 10 {
							fmt.Fprintf(&desc, "  ... (%d more lines)\n", len(panicLines)-10)
						}

						findings = append(findings, types.Finding{
							Severity:    types.SeverityCritical,
							Category:    types.CategoryHealth,
							Title:       fmt.Sprintf("Agent crash detected in %s", component),
							Description: desc.String(),
							Suggestion:  "This crash may be a known issue. Check if an agent upgrade is available. If this persists, file a bug report with the full stack trace.",
							SourceFile:  source,
						})
					}
					panicLines = nil
				}
			}
		}

		// Handle case where panic was the last thing in the log (no trailing line to close it)
		if inPanic && len(panicLines) > 2 {
			panicMsg := ""
			for _, pl := range panicLines {
				if strings.Contains(pl, "panic:") || strings.Contains(pl, "runtime error:") {
					panicMsg = strings.TrimSpace(pl)
					break
				}
			}
			if panicMsg != "" {
				var desc strings.Builder
				fmt.Fprintf(&desc, "Crash at end of %s log:\n  %s\n", component, truncate(panicMsg, 150))
				showLines := len(panicLines)
				if showLines > 8 {
					showLines = 8
				}
				for k := 0; k < showLines; k++ {
					fmt.Fprintf(&desc, "  %s\n", truncate(panicLines[k], 120))
				}

				findings = append(findings, types.Finding{
					Severity:    types.SeverityCritical,
					Category:    types.CategoryHealth,
					Title:       fmt.Sprintf("Agent crash at end of %s log", component),
					Description: desc.String(),
					Suggestion:  "The crash appears at the end of the log, suggesting the agent terminated. Check if the agent restarted (systemctl status datadog-agent).",
					SourceFile:  source,
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Root cause inference
// ---------------------------------------------------------------------------

func (a *LogInsightAnalyzer) inferRootCauses(errors []logEntry) []types.Finding {
	var findings []types.Finding

	// Classify all errors
	classCounts := make(map[errorClass]int)
	for _, e := range errors {
		cls := classifyError(e.message)
		classCounts[cls]++
	}

	// Build a list of active root cause signals
	type rootCauseSignal struct {
		cause       string
		confidence  string
		description string
		remediation string
	}

	var signals []rootCauseSignal

	tlsCount := classCounts[errClassTLS]
	networkCount := classCounts[errClassNetwork]
	timeoutCount := classCounts[errClassTimeout]
	resourceCount := classCounts[errClassResource]
	permCount := classCounts[errClassPermission]
	configCount := classCounts[errClassConfig]
	crashCount := classCounts[errClassCrash]

	totalClassified := 0
	for _, c := range classCounts {
		totalClassified += c
	}

	// Network connectivity issue
	if networkCount+timeoutCount+tlsCount > 0 {
		netTotal := networkCount + timeoutCount + tlsCount
		if totalClassified > 0 && float64(netTotal)/float64(totalClassified) > 0.5 {
			cause := "Network connectivity"
			desc := fmt.Sprintf("%d network + %d timeout + %d TLS errors = %d total (%.0f%% of all errors)",
				networkCount, timeoutCount, tlsCount, netTotal,
				float64(netTotal)/float64(totalClassified)*100)

			if tlsCount > networkCount && tlsCount > timeoutCount {
				cause = "TLS/Certificate issue"
				signals = append(signals, rootCauseSignal{
					cause:      cause,
					confidence: "high",
					description: desc + "\nTLS errors are dominant, suggesting certificate or SSL inspection problems.",
					remediation: "1. Check certificate validity: openssl s_client -connect <endpoint>:443\n" +
						"2. Verify no SSL inspection/MITM proxy is active\n" +
						"3. Check if agent CA bundle includes custom CA certs\n" +
						"4. As a last resort: skip_ssl_validation: true (NOT recommended for production)",
				})
			} else if timeoutCount > networkCount {
				cause = "Service/network latency"
				signals = append(signals, rootCauseSignal{
					cause:      cause,
					confidence: "medium",
					description: desc + "\nTimeouts dominate, suggesting slow responses rather than complete failures.",
					remediation: "1. Check network latency to Datadog: curl -o /dev/null -s -w '%%{time_total}' https://app.datadoghq.com/api/v1/validate\n" +
						"2. Review proxy performance if using one\n" +
						"3. Check for network congestion or bandwidth limits\n" +
						"4. Consider increasing agent timeout settings",
				})
			} else {
				signals = append(signals, rootCauseSignal{
					cause:      cause,
					confidence: "high",
					description: desc + "\nDirect connection failures indicate the agent cannot reach its targets.",
					remediation: "1. Check DNS resolution: nslookup app.datadoghq.com\n" +
						"2. Check firewall rules for outbound HTTPS (port 443)\n" +
						"3. Verify proxy configuration in datadog.yaml\n" +
						"4. Test connectivity: curl -v https://app.datadoghq.com/api/v1/validate?api_key=<key>",
				})
			}
		}
	}

	// Resource exhaustion
	if resourceCount > 0 {
		signals = append(signals, rootCauseSignal{
			cause:      "Resource exhaustion",
			confidence: "high",
			description: fmt.Sprintf("%d resource-related errors (OOM, file descriptors, disk space)", resourceCount),
			remediation: "1. Check memory usage: free -h, check container memory limits\n" +
				"2. Check file descriptors: ulimit -n, cat /proc/$(pidof agent)/limits\n" +
				"3. Check disk space: df -h\n" +
				"4. Review agent memory_limit configuration\n" +
				"5. Consider reducing DogStatsD cardinality or number of checks",
		})
	}

	// Permission issues
	if permCount > 3 {
		signals = append(signals, rootCauseSignal{
			cause:       "Permission/access issues",
			confidence:  "high",
			description: fmt.Sprintf("%d permission-related errors", permCount),
			remediation: "1. Verify dd-agent user exists and has correct group membership\n" +
				"2. Check file ownership: ls -la /etc/datadog-agent/\n" +
				"3. Review SELinux/AppArmor: getenforce, aa-status\n" +
				"4. In containers: check securityContext and service account permissions",
		})
	}

	// Configuration issues
	if configCount > 3 {
		signals = append(signals, rootCauseSignal{
			cause:       "Configuration errors",
			confidence:  "medium",
			description: fmt.Sprintf("%d configuration-related errors (invalid YAML, missing files, unknown keys)", configCount),
			remediation: "1. Validate YAML syntax: python -c 'import yaml; yaml.safe_load(open(\"/etc/datadog-agent/datadog.yaml\"))'\n" +
				"2. Check config-check.log for detailed configuration errors\n" +
				"3. Review recent changes to datadog.yaml or conf.d/\n" +
				"4. Run: datadog-agent configcheck",
		})
	}

	// Crashes
	if crashCount > 0 {
		signals = append(signals, rootCauseSignal{
			cause:       "Agent crash/panic",
			confidence:  "high",
			description: fmt.Sprintf("%d crash-related errors (panics, fatal errors, signals)", crashCount),
			remediation: "1. Check if agent version is up to date: datadog-agent version\n" +
				"2. Search known issues: https://github.com/DataDog/datadog-agent/issues\n" +
				"3. Collect core dump if available: /var/log/datadog/\n" +
				"4. If persistent, file a bug report with the full stack trace",
		})
	}

	if len(signals) == 0 {
		return nil
	}

	// Sort by confidence and impact
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].confidence == signals[j].confidence {
			return signals[i].cause < signals[j].cause
		}
		return signals[i].confidence == "high"
	})

	var desc strings.Builder
	desc.WriteString("Root cause analysis based on error patterns:\n\n")

	for i, sig := range signals {
		fmt.Fprintf(&desc, "%d. %s [confidence: %s]\n", i+1, sig.cause, sig.confidence)
		fmt.Fprintf(&desc, "   %s\n", sig.description)
		desc.WriteString("   Remediation steps:\n")
		for _, line := range strings.Split(sig.remediation, "\n") {
			fmt.Fprintf(&desc, "   %s\n", line)
		}
		desc.WriteString("\n")
	}

	findings = append(findings, types.Finding{
		Severity:    types.SeverityError,
		Category:    types.CategoryGeneral,
		Title:       fmt.Sprintf("Root cause analysis: %d probable cause(s) identified", len(signals)),
		Description: desc.String(),
		SourceFile:  "logs/",
	})

	return findings
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// normalizeErrorMsg strips timestamps, file references, and variable parts
// from error messages to enable grouping/deduplication.
func normalizeErrorMsg(msg string) string {
	// Remove timestamps
	msg = timestampRe.ReplaceAllString(msg, "")
	// Remove file:line references
	fileLineRe := regexp.MustCompile(`\([^)]+\.go:\d+ in [^)]+\)`)
	msg = fileLineRe.ReplaceAllString(msg, "")
	// Remove hex addresses
	hexRe := regexp.MustCompile(`0x[0-9a-fA-F]+`)
	msg = hexRe.ReplaceAllString(msg, "0x...")
	// Remove IP:port combinations
	ipRe := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+`)
	msg = ipRe.ReplaceAllString(msg, "<ip:port>")
	// Remove UUIDs
	uuidRe := regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	msg = uuidRe.ReplaceAllString(msg, "<uuid>")
	// Collapse whitespace
	msg = strings.Join(strings.Fields(msg), " ")
	// Trim pipes
	msg = strings.Trim(msg, "| ")
	return truncate(msg, 120)
}
