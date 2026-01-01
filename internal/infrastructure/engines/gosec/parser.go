package gosec

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// GosecOutput represents the JSON output structure from gosec.
type GosecOutput struct {
	Issues []GosecIssue `json:"Issues"`
	Stats  GosecStats   `json:"Stats"`
}

// GosecIssue represents a single issue in gosec output.
type GosecIssue struct {
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Cwe        GosecCwe `json:"cwe"`
	RuleID     string   `json:"rule_id"`
	Details    string   `json:"details"`
	File       string   `json:"file"`
	Code       string   `json:"code"`
	Line       string   `json:"line"`
	Column     string   `json:"column"`
	Nosec      bool     `json:"nosec"`
}

// GosecCwe represents CWE information.
type GosecCwe struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// GosecStats represents scanning statistics.
type GosecStats struct {
	Files int `json:"files"`
	Lines int `json:"lines"`
	Nosec int `json:"nosec"`
	Found int `json:"found"`
}

// Parser converts gosec JSON output to RawFindings.
type Parser struct{}

// NewParser creates a new gosec parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts gosec JSON output to raw findings.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	var output GosecOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gosec output: %w", err)
	}

	findings := make([]ports.RawFinding, 0, len(output.Issues))
	for _, issue := range output.Issues {
		// Skip nosec-annotated issues
		if issue.Nosec {
			continue
		}

		finding := p.issueToRawFinding(issue)
		findings = append(findings, finding)
	}

	return findings, nil
}

// issueToRawFinding converts a gosec issue to a raw finding.
func (p *Parser) issueToRawFinding(issue GosecIssue) ports.RawFinding {
	startLine := parseLineNumber(issue.Line)
	startColumn := parseLineNumber(issue.Column)

	// Gosec doesn't provide end line/column, estimate based on code
	endLine := startLine
	endColumn := startColumn + 20 // Reasonable default

	// Build metadata
	metadata := make(map[string]string)
	if issue.Cwe.ID != "" {
		metadata["cwe_id"] = issue.Cwe.ID
		metadata["cwe_url"] = issue.Cwe.URL
	}

	return ports.RawFinding{
		RuleID:      issue.RuleID,
		Message:     issue.Details,
		Severity:    issue.Severity,
		Confidence:  issue.Confidence,
		File:        issue.File,
		StartLine:   startLine,
		StartColumn: startColumn,
		EndLine:     endLine,
		EndColumn:   endColumn,
		Snippet:     issue.Code,
		Metadata:    metadata,
	}
}

// parseLineNumber safely parses a line/column string to int.
func parseLineNumber(s string) int {
	// Gosec may return "10-12" for multi-line issues
	if idx := len(s); idx > 0 {
		for i, c := range s {
			if c == '-' {
				s = s[:i]
				break
			}
		}
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return 1
	}
	return n
}

// ParseStats extracts statistics from gosec output.
func (p *Parser) ParseStats(data []byte) (GosecStats, error) {
	if len(data) == 0 {
		return GosecStats{}, nil
	}

	var output GosecOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return GosecStats{}, fmt.Errorf("failed to unmarshal gosec output: %w", err)
	}

	return output.Stats, nil
}

// GetIssueCount returns the number of issues (excluding nosec) in the output.
func (p *Parser) GetIssueCount(data []byte) (int, error) {
	findings, err := p.Parse(data)
	if err != nil {
		return 0, err
	}
	return len(findings), nil
}
