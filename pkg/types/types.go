// Package types defines the core types used throughout the flare analysis tool.
package types

import "fmt"

// Severity classifies the importance of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Category classifies what area a finding belongs to.
type Category string

const (
	CategoryConfig       Category = "Configuration"
	CategoryConnectivity Category = "Connectivity"
	CategoryHealth       Category = "Health"
	CategoryLogs         Category = "Logs"
	CategoryChecks       Category = "Checks"
	CategoryResources    Category = "Resources"
	CategorySecurity     Category = "Security"
	CategoryContainer    Category = "Container"
	CategoryMetadata     Category = "Metadata"
	CategoryGeneral      Category = "General"
)

// Finding represents a single insight or issue discovered in the flare.
type Finding struct {
	Severity    Severity
	Category    Category
	Title       string
	Description string
	SourceFile  string
	Suggestion  string
}

func (f Finding) String() string {
	s := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Category, f.Title)
	if f.Description != "" {
		s += "\n    " + f.Description
	}
	if f.Suggestion != "" {
		s += "\n    -> " + f.Suggestion
	}
	if f.SourceFile != "" {
		s += fmt.Sprintf("\n    (source: %s)", f.SourceFile)
	}
	return s
}

// FlareInfo stores high-level information about the flare archive.
type FlareInfo struct {
	Hostname      string
	AgentVersion  string
	Platform      string
	InstallMethod string
	FlareTime     string
	LogLevel      string
	FileCount     int
	TotalSize     int64
}

// AnalysisReport is the final output of the analysis.
type AnalysisReport struct {
	FlareInfo FlareInfo
	Findings  []Finding
	Summary   ReportSummary
}

// ReportSummary provides aggregate stats about the analysis.
type ReportSummary struct {
	TotalFindings     int
	CriticalCount     int
	ErrorCount        int
	WarningCount      int
	InfoCount         int
	AnalyzersRun      int
	FilesAnalyzed     int
	MissingFiles      []string
	AvailableSections []string
}
