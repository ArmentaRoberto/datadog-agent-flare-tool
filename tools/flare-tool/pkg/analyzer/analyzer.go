// Package analyzer defines the Analyzer interface and registry.
package analyzer

import (
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/extractor"
	"github.com/DataDog/datadog-agent/tools/flare-tool/pkg/types"
)

// Analyzer inspects specific parts of a flare archive and produces findings.
type Analyzer interface {
	// Name returns the human-readable name of this analyzer.
	Name() string
	// Analyze runs the analysis against the given archive.
	Analyze(archive *extractor.FlareArchive) []types.Finding
}

// Registry holds all registered analyzers.
var Registry []Analyzer

// Register adds an analyzer to the global registry.
func Register(a Analyzer) {
	Registry = append(Registry, a)
}

func init() {
	Register(&ConfigAnalyzer{})
	Register(&StatusAnalyzer{})
	Register(&HealthAnalyzer{})
	Register(&LogAnalyzer{})
	Register(&ConnectivityAnalyzer{})
	Register(&ChecksAnalyzer{})
	Register(&ResourceAnalyzer{})
	Register(&ContainerAnalyzer{})
	Register(&SecurityAnalyzer{})
	Register(&MetadataAnalyzer{})
	Register(&CompletenessAnalyzer{})
}
