package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/pkg/redact"
)

// SARIFVersion is the SARIF specification version.
const SARIFVersion = "2.1.0"

// SARIFSchema is the JSON schema URL for SARIF.
const SARIFSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// SARIFWriter writes SARIF-formatted output for GitHub Security integration.
type SARIFWriter struct {
	out      io.Writer
	redactor *redact.Redactor
	toolName string
	toolVer  string
	basePath string // Repository root for converting absolute paths to relative
}

// SARIFOption configures the SARIF writer.
type SARIFOption func(*SARIFWriter)

// WithSARIFOutput sets the output writer.
func WithSARIFOutput(out io.Writer) SARIFOption {
	return func(w *SARIFWriter) {
		w.out = out
	}
}

// WithToolInfo sets tool name and version.
func WithToolInfo(name, version string) SARIFOption {
	return func(w *SARIFWriter) {
		w.toolName = name
		w.toolVer = version
	}
}

// WithBasePath sets the repository root path for converting absolute paths to relative.
func WithBasePath(basePath string) SARIFOption {
	return func(w *SARIFWriter) {
		w.basePath = basePath
	}
}

// NewSARIFWriter creates a new SARIF writer.
func NewSARIFWriter(opts ...SARIFOption) *SARIFWriter {
	// Get current working directory as default base path for relative path conversion
	basePath, _ := os.Getwd()

	w := &SARIFWriter{
		out:      os.Stdout,
		redactor: redact.New(redact.WithPartialDisplay(4, 4)),
		toolName: "VerdictSec",
		toolVer:  "1.0.0",
		basePath: basePath,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// SetOutput sets the output destination.
func (w *SARIFWriter) SetOutput(out io.Writer) {
	w.out = out
}

// Close closes any open file handles.
func (w *SARIFWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// WriteAssessment writes the assessment as SARIF.
func (w *SARIFWriter) WriteAssessment(a *assessment.Assessment, result services.EvaluationResult) error {
	sarif := w.buildSARIF(a, result)
	return w.writeJSON(sarif)
}

// WriteSummary writes a brief summary (same as full assessment for SARIF).
func (w *SARIFWriter) WriteSummary(a *assessment.Assessment, result services.EvaluationResult) error {
	return w.WriteAssessment(a, result)
}

// WriteProgress is a no-op for SARIF (no progress in file output).
func (w *SARIFWriter) WriteProgress(_ string) error {
	return nil
}

// WriteError is a no-op for SARIF (errors don't go in SARIF output).
func (w *SARIFWriter) WriteError(_ error) error {
	return nil
}

// Flush ensures all output is written.
func (w *SARIFWriter) Flush() error {
	return nil
}

// buildSARIF creates the SARIF output structure.
func (w *SARIFWriter) buildSARIF(a *assessment.Assessment, result services.EvaluationResult) SARIFLog {
	// Build rules from findings
	rulesMap := make(map[string]*SARIFRule)
	var results []SARIFResult

	for _, f := range a.Findings() {
		// Create or update rule
		ruleID := w.buildRuleID(f)
		if _, exists := rulesMap[ruleID]; !exists {
			rulesMap[ruleID] = w.buildRule(f)
		}

		// Create result
		results = append(results, w.buildResult(f, ruleID, result))
	}

	// Convert rules map to slice
	var rules []SARIFRule
	for _, rule := range rulesMap {
		rules = append(rules, *rule)
	}

	// Build run
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:            w.toolName,
				Version:         w.toolVer,
				InformationURI:  "https://github.com/felixgeelhaar/verdictsec",
				SemanticVersion: w.toolVer,
				Rules:           rules,
			},
		},
		Results: results,
		Invocations: []SARIFInvocation{
			{
				ExecutionSuccessful: true,
				StartTimeUTC:        a.StartedAt().Format(time.RFC3339),
				EndTimeUTC:          a.CompletedAt().Format(time.RFC3339),
			},
		},
	}

	return SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs:    []SARIFRun{run},
	}
}

// buildRuleID creates a unique rule ID.
func (w *SARIFWriter) buildRuleID(f *finding.Finding) string {
	return fmt.Sprintf("%s/%s", f.EngineID(), f.RuleID())
}

// buildRule creates a SARIF rule from a finding.
func (w *SARIFWriter) buildRule(f *finding.Finding) *SARIFRule {
	rule := &SARIFRule{
		ID:               w.buildRuleID(f),
		Name:             f.RuleID(),
		ShortDescription: SARIFMessage{Text: f.Title()},
		FullDescription:  SARIFMessage{Text: f.Description()},
		DefaultConfiguration: SARIFRuleConfig{
			Level: w.severityToLevel(f.EffectiveSeverity()),
		},
		Properties: SARIFRuleProperties{
			Precision:       w.confidenceToPrecision(f.Confidence()),
			SecuritySeverity: w.severityToScore(f.EffectiveSeverity()),
			Tags:            w.buildTags(f),
		},
	}

	// Add help URL if CWE is available
	if f.CWEID() != "" {
		rule.HelpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
			strings.TrimPrefix(f.CWEID(), "CWE-"))
	}

	return rule
}

// buildResult creates a SARIF result from a finding.
func (w *SARIFWriter) buildResult(f *finding.Finding, ruleID string, evalResult services.EvaluationResult) SARIFResult {
	result := SARIFResult{
		RuleID:  ruleID,
		Level:   w.severityToLevel(f.EffectiveSeverity()),
		Message: SARIFMessage{Text: f.Title()},
		Locations: []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI:       w.normalizeFilePath(f.Location().File()),
						URIBaseID: "%SRCROOT%",
					},
					Region: SARIFRegion{
						StartLine:   f.Location().Line(),
						StartColumn: f.Location().Column(),
						EndLine:     f.Location().EndLine(),
						EndColumn:   f.Location().EndColumn(),
					},
				},
			},
		},
		Fingerprints: map[string]string{
			"verdictsec/v1": f.Fingerprint().Value(),
		},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": f.Fingerprint().Value()[:16],
		},
	}

	// Add suppression info if applicable
	if isInSlice(f, evalResult.Suppressed) {
		result.Suppressions = []SARIFSuppression{
			{
				Kind: "inSource",
			},
		}
	} else if isInSlice(f, evalResult.Existing) {
		result.BaselineState = "unchanged"
	} else {
		result.BaselineState = "new"
	}

	// Add related locations for CVE/CWE
	if f.CVEID() != "" {
		result.RelatedLocations = append(result.RelatedLocations, SARIFRelatedLocation{
			ID:      1,
			Message: SARIFMessage{Text: fmt.Sprintf("Related CVE: %s", f.CVEID())},
		})
	}

	return result
}

// severityToLevel converts finding severity to SARIF level.
func (w *SARIFWriter) severityToLevel(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// severityToScore converts severity to a numeric security severity score (0.0-10.0).
func (w *SARIFWriter) severityToScore(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "9.0"
	case finding.SeverityHigh:
		return "7.0"
	case finding.SeverityMedium:
		return "5.0"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// confidenceToPrecision converts confidence to SARIF precision.
func (w *SARIFWriter) confidenceToPrecision(conf finding.Confidence) string {
	switch conf {
	case finding.ConfidenceHigh:
		return "high"
	case finding.ConfidenceMedium:
		return "medium"
	case finding.ConfidenceLow:
		return "low"
	default:
		return "unknown"
	}
}

// buildTags creates tags for a finding.
func (w *SARIFWriter) buildTags(f *finding.Finding) []string {
	tags := []string{"security"}

	switch f.Type() {
	case finding.FindingTypeSAST:
		tags = append(tags, "static-analysis", "code-quality")
	case finding.FindingTypeVuln:
		tags = append(tags, "vulnerability", "dependency")
	case finding.FindingTypeSecret:
		tags = append(tags, "secret", "credential")
	}

	if f.CWEID() != "" {
		tags = append(tags, f.CWEID())
	}

	return tags
}

// normalizeFilePath normalizes file paths for SARIF.
// It converts absolute paths to relative paths based on the configured basePath.
func (w *SARIFWriter) normalizeFilePath(path string) string {
	// Convert to forward slashes for consistency (platform-independent)
	path = strings.ReplaceAll(path, "\\", "/")

	// If we have a base path, try to make the path relative
	if w.basePath != "" {
		basePath := strings.ReplaceAll(w.basePath, "\\", "/")
		// Ensure basePath ends with a slash for proper prefix matching
		if !strings.HasSuffix(basePath, "/") {
			basePath += "/"
		}
		// Strip base path prefix if present (works for both Unix and Windows paths)
		path = strings.TrimPrefix(path, basePath)
	}

	// Remove leading ./ if present
	path = strings.TrimPrefix(path, "./")
	return path
}

// writeJSON writes a value as JSON.
func (w *SARIFWriter) writeJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	_, err = fmt.Fprintln(w.out, string(data))
	return err
}

// SARIF data structures

// SARIFLog is the top-level SARIF structure.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule.
type SARIFRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     SARIFMessage        `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage        `json:"fullDescription,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration SARIFRuleConfig     `json:"defaultConfiguration,omitempty"`
	Properties           SARIFRuleProperties `json:"properties,omitempty"`
}

// SARIFRuleConfig is the default configuration for a rule.
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"`
}

// SARIFRuleProperties are additional rule properties.
type SARIFRuleProperties struct {
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// SARIFResult is an individual finding.
type SARIFResult struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level,omitempty"`
	Message             SARIFMessage           `json:"message"`
	Locations           []SARIFLocation        `json:"locations,omitempty"`
	RelatedLocations    []SARIFRelatedLocation `json:"relatedLocations,omitempty"`
	Fingerprints        map[string]string      `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	BaselineState       string                 `json:"baselineState,omitempty"`
	Suppressions        []SARIFSuppression     `json:"suppressions,omitempty"`
}

// SARIFMessage is a message with text.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes a location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a physical file location.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation is the artifact (file) location.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion is a region within a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFRelatedLocation is a related location.
type SARIFRelatedLocation struct {
	ID      int          `json:"id"`
	Message SARIFMessage `json:"message,omitempty"`
}

// SARIFSuppression indicates a finding is suppressed.
type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// SARIFInvocation describes a tool invocation.
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// Ensure SARIFWriter implements the interface.
var _ ports.SARIFWriter = (*SARIFWriter)(nil)
