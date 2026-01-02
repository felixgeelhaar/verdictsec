package staticcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// StaticcheckIssue represents a single issue in staticcheck JSON output.
// Staticcheck outputs one JSON object per line (JSON Lines format).
type StaticcheckIssue struct {
	Code     string             `json:"code"`
	Severity string             `json:"severity"`
	Location StaticcheckLocation `json:"location"`
	End      StaticcheckLocation `json:"end"`
	Message  string             `json:"message"`
}

// StaticcheckLocation represents file location in staticcheck output.
type StaticcheckLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// Parser converts staticcheck JSON output to RawFindings.
type Parser struct{}

// NewParser creates a new staticcheck parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts staticcheck JSON output to raw findings.
// Staticcheck outputs JSON Lines format (one JSON object per line).
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	var findings []ports.RawFinding

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var issue StaticcheckIssue
		if err := json.Unmarshal(line, &issue); err != nil {
			return nil, fmt.Errorf("failed to unmarshal staticcheck output at line %d: %w", lineNum, err)
		}

		finding := p.issueToRawFinding(issue)
		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan staticcheck output: %w", err)
	}

	return findings, nil
}

// issueToRawFinding converts a staticcheck issue to a raw finding.
func (p *Parser) issueToRawFinding(issue StaticcheckIssue) ports.RawFinding {
	startLine := issue.Location.Line
	startColumn := issue.Location.Column
	endLine := issue.End.Line
	endColumn := issue.End.Column

	// If end location is not provided, estimate
	if endLine == 0 {
		endLine = startLine
	}
	if endColumn == 0 {
		endColumn = startColumn + 20 // Reasonable default
	}

	// Build metadata
	metadata := make(map[string]string)
	metadata["check_code"] = issue.Code

	return ports.RawFinding{
		RuleID:      issue.Code,
		Message:     issue.Message,
		Severity:    issue.Severity,
		Confidence:  "HIGH", // staticcheck has high confidence
		File:        issue.Location.File,
		StartLine:   startLine,
		StartColumn: startColumn,
		EndLine:     endLine,
		EndColumn:   endColumn,
		Metadata:    metadata,
	}
}

// GetIssueCount returns the number of issues in the output.
func (p *Parser) GetIssueCount(data []byte) (int, error) {
	findings, err := p.Parse(data)
	if err != nil {
		return 0, err
	}
	return len(findings), nil
}
