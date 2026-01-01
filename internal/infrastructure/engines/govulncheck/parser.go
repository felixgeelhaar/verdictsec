package govulncheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// GovulncheckMessage represents a single JSON message from govulncheck output.
// Govulncheck outputs newline-delimited JSON messages.
type GovulncheckMessage struct {
	Config   *ConfigMessage   `json:"config,omitempty"`
	Progress *ProgressMessage `json:"progress,omitempty"`
	OSV      *OSVMessage      `json:"osv,omitempty"`
	Finding  *FindingMessage  `json:"finding,omitempty"`
}

// ConfigMessage contains scan configuration.
type ConfigMessage struct {
	GoVersion    string `json:"go_version"`
	ScannerName  string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version"`
	DB           string `json:"db"`
	DBLastMod    string `json:"db_last_modified"`
	ScanLevel    string `json:"scan_level"`
}

// ProgressMessage contains progress updates.
type ProgressMessage struct {
	Message string `json:"message"`
}

// OSVMessage contains OSV vulnerability data.
type OSVMessage struct {
	SchemaVersion string        `json:"schema_version"`
	ID            string        `json:"id"`
	Modified      string        `json:"modified"`
	Published     string        `json:"published"`
	Aliases       []string      `json:"aliases"`
	Summary       string        `json:"summary"`
	Details       string        `json:"details"`
	Affected      []OSVAffected `json:"affected"`
	References    []OSVRef      `json:"references"`
	DatabaseSpecific *OSVDatabaseSpecific `json:"database_specific,omitempty"`
}

// OSVAffected contains affected package information.
type OSVAffected struct {
	Package   OSVPackage  `json:"package"`
	Ranges    []OSVRange  `json:"ranges"`
	EcosystemSpecific *OSVEcosystem `json:"ecosystem_specific,omitempty"`
}

// OSVPackage contains package info.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVRange contains version ranges.
type OSVRange struct {
	Type   string      `json:"type"`
	Events []OSVEvent  `json:"events"`
}

// OSVEvent is a version event.
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// OSVRef is a reference.
type OSVRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// OSVEcosystem contains ecosystem-specific data.
type OSVEcosystem struct {
	Imports []OSVImport `json:"imports,omitempty"`
}

// OSVImport contains import info.
type OSVImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

// OSVDatabaseSpecific contains database-specific data.
type OSVDatabaseSpecific struct {
	URL string `json:"url,omitempty"`
}

// FindingMessage contains a vulnerability finding.
type FindingMessage struct {
	OSV   string       `json:"osv"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Trace []TraceEntry `json:"trace"`
}

// TraceEntry is an entry in the call trace.
type TraceEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Package string `json:"package"`
	Function string `json:"function,omitempty"`
	Position *Position `json:"position,omitempty"`
}

// Position contains source position.
type Position struct {
	Filename string `json:"filename"`
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// Parser converts govulncheck JSON output to RawFindings.
type Parser struct {
	osvCache map[string]*OSVMessage
}

// NewParser creates a new govulncheck parser.
func NewParser() *Parser {
	return &Parser{
		osvCache: make(map[string]*OSVMessage),
	}
}

// Parse converts govulncheck JSON output to raw findings.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return []ports.RawFinding{}, nil
	}

	// Parse newline-delimited JSON messages
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line size

	var findings []ports.RawFinding

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg GovulncheckMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			// Skip non-JSON lines
			continue
		}

		// Cache OSV entries
		if msg.OSV != nil {
			p.osvCache[msg.OSV.ID] = msg.OSV
		}

		// Process findings
		if msg.Finding != nil {
			finding := p.findingToRaw(msg.Finding)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan govulncheck output: %w", err)
	}

	return findings, nil
}

// findingToRaw converts a govulncheck finding to a raw finding.
func (p *Parser) findingToRaw(f *FindingMessage) *ports.RawFinding {
	if f == nil || len(f.Trace) == 0 {
		return nil
	}

	// Get OSV data if available
	osv := p.osvCache[f.OSV]

	// Build message from OSV summary
	message := fmt.Sprintf("Vulnerability %s", f.OSV)
	if osv != nil && osv.Summary != "" {
		message = osv.Summary
	}

	// Determine file and location from trace
	file := ""
	line := 0
	column := 0

	// Look for position in trace (first entry with position)
	for _, entry := range f.Trace {
		if entry.Position != nil {
			file = entry.Position.Filename
			line = entry.Position.Line
			column = entry.Position.Column
			break
		}
	}

	// If no position, use module info
	if file == "" && len(f.Trace) > 0 {
		file = f.Trace[0].Package
	}

	// Determine severity from OSV aliases (CVE -> CVSS lookup would need external data)
	// Default to HIGH for vulnerabilities
	severity := "HIGH"

	// Build metadata
	metadata := make(map[string]string)
	metadata["osv_id"] = f.OSV

	// Add CVE if available
	if osv != nil {
		for _, alias := range osv.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				metadata["cve_id"] = alias
				break
			}
		}

		// Add module info
		if len(osv.Affected) > 0 {
			metadata["module"] = osv.Affected[0].Package.Name
		}

		// Add details
		if osv.Details != "" {
			metadata["details"] = osv.Details
		}
	}

	// Add trace info
	if len(f.Trace) > 0 {
		entry := f.Trace[0]
		metadata["vulnerable_module"] = entry.Module
		metadata["vulnerable_version"] = entry.Version
		if entry.Function != "" {
			metadata["vulnerable_function"] = entry.Function
		}
	}

	return &ports.RawFinding{
		RuleID:      f.OSV,
		Message:     message,
		Severity:    severity,
		Confidence:  "HIGH",
		File:        file,
		StartLine:   line,
		StartColumn: column,
		EndLine:     line,
		EndColumn:   column + 10,
		Snippet:     "",
		Metadata:    metadata,
	}
}

// GetVulnerabilityCount returns the number of unique vulnerabilities.
func (p *Parser) GetVulnerabilityCount(data []byte) (int, error) {
	findings, err := p.Parse(data)
	if err != nil {
		return 0, err
	}
	return len(findings), nil
}
