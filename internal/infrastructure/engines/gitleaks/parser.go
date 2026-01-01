package gitleaks

import (
	"encoding/json"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// GitleaksOutput represents a single finding in gitleaks output.
type GitleaksOutput struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	SymlinkFile string `json:"SymlinkFile"`
	Commit      string `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
	Author      string `json:"Author"`
	Email       string `json:"Email"`
	Date        string `json:"Date"`
	Message     string `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

// Parser converts gitleaks JSON output to RawFindings.
type Parser struct{}

// NewParser creates a new gitleaks parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts gitleaks JSON output to raw findings.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	var outputs []GitleaksOutput
	if err := json.Unmarshal(data, &outputs); err != nil {
		// Try parsing as empty result or error message
		if string(data) == "null" || string(data) == "[]" {
			return []ports.RawFinding{}, nil
		}
		return nil, fmt.Errorf("failed to unmarshal gitleaks output: %w", err)
	}

	findings := make([]ports.RawFinding, 0, len(outputs))
	for _, output := range outputs {
		finding := p.outputToRawFinding(output)
		findings = append(findings, finding)
	}

	return findings, nil
}

// outputToRawFinding converts a gitleaks output to a raw finding.
func (p *Parser) outputToRawFinding(output GitleaksOutput) ports.RawFinding {
	// Build metadata
	metadata := make(map[string]string)

	// Store the secret for potential redaction
	metadata["secret"] = output.Secret
	metadata["match"] = output.Match

	if output.Entropy > 0 {
		metadata["entropy"] = fmt.Sprintf("%.2f", output.Entropy)
	}

	if output.Commit != "" {
		metadata["commit"] = output.Commit
	}

	if output.Author != "" {
		metadata["author"] = output.Author
	}

	if len(output.Tags) > 0 {
		metadata["tags"] = fmt.Sprintf("%v", output.Tags)
	}

	if output.Fingerprint != "" {
		metadata["gitleaks_fingerprint"] = output.Fingerprint
	}

	// Secrets are always HIGH severity
	severity := "HIGH"

	// Build message
	message := output.Description
	if message == "" {
		message = fmt.Sprintf("Secret detected: %s", output.RuleID)
	}

	return ports.RawFinding{
		RuleID:      output.RuleID,
		Message:     message,
		Severity:    severity,
		Confidence:  "HIGH",
		File:        output.File,
		StartLine:   output.StartLine,
		StartColumn: output.StartColumn,
		EndLine:     output.EndLine,
		EndColumn:   output.EndColumn,
		Snippet:     output.Match, // Will be redacted later
		Metadata:    metadata,
	}
}

// GetSecretCount returns the number of secrets found.
func (p *Parser) GetSecretCount(data []byte) (int, error) {
	findings, err := p.Parse(data)
	if err != nil {
		return 0, err
	}
	return len(findings), nil
}
