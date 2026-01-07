// Package trivy provides an adapter for the Trivy security scanner.
package trivy

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// Parser parses Trivy JSON output.
type Parser struct{}

// NewParser creates a new Trivy parser.
func NewParser() *Parser {
	return &Parser{}
}

// TrivyReport represents the top-level Trivy JSON output.
type TrivyReport struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`
	ArtifactType  string         `json:"ArtifactType"`
	Results       []TrivyResult  `json:"Results"`
}

// TrivyResult represents a single result from Trivy (per target/file).
type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
	Secrets         []TrivySecret        `json:"Secrets"`
}

// TrivyVulnerability represents a vulnerability finding.
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgID            string   `json:"PkgID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CVSS             CVSS     `json:"CVSS"`
	CweIDs           []string `json:"CweIDs"`
	PublishedDate    string   `json:"PublishedDate"`
	LastModifiedDate string   `json:"LastModifiedDate"`
}

// CVSS contains CVSS scoring information.
type CVSS struct {
	NVD    CVSSSource `json:"nvd"`
	RedHat CVSSSource `json:"redhat"`
}

// CVSSSource contains CVSS scores from a specific source.
type CVSSSource struct {
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

// TrivySecret represents a secret finding.
type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      Code   `json:"Code"`
	Match     string `json:"Match"`
}

// Code contains the code snippet context.
type Code struct {
	Lines []CodeLine `json:"Lines"`
}

// CodeLine represents a single line of code context.
type CodeLine struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

// Parse parses Trivy JSON output into raw findings.
func (p *Parser) Parse(data []byte) ([]ports.RawFinding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON: %w", err)
	}

	var findings []ports.RawFinding

	for _, result := range report.Results {
		// Parse vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := p.parseVulnerability(result.Target, vuln)
			findings = append(findings, finding)
		}

		// Parse secrets
		for _, secret := range result.Secrets {
			finding := p.parseSecret(result.Target, secret)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// parseVulnerability converts a Trivy vulnerability to a RawFinding.
func (p *Parser) parseVulnerability(target string, vuln TrivyVulnerability) ports.RawFinding {
	metadata := map[string]string{
		"type":              "vulnerability",
		"package":           vuln.PkgName,
		"installed_version": vuln.InstalledVersion,
		"vulnerability_id":  vuln.VulnerabilityID,
		"target":            target,
	}

	if vuln.FixedVersion != "" {
		metadata["fixed_version"] = vuln.FixedVersion
	}

	if vuln.PrimaryURL != "" {
		metadata["url"] = vuln.PrimaryURL
	}

	if len(vuln.CweIDs) > 0 {
		metadata["cwe"] = vuln.CweIDs[0]
	}

	// Extract CVSS score
	cvssScore := vuln.CVSS.NVD.V3Score
	if cvssScore == 0 {
		cvssScore = vuln.CVSS.NVD.V2Score
	}
	if cvssScore == 0 {
		cvssScore = vuln.CVSS.RedHat.V3Score
	}
	if cvssScore > 0 {
		metadata["cvss_score"] = strconv.FormatFloat(cvssScore, 'f', 1, 64)
	}

	// Build message
	message := vuln.Title
	if message == "" {
		message = vuln.Description
	}
	if message == "" {
		message = fmt.Sprintf("Vulnerability %s in %s", vuln.VulnerabilityID, vuln.PkgName)
	}

	return ports.RawFinding{
		RuleID:     vuln.VulnerabilityID,
		Message:    message,
		Severity:   vuln.Severity,
		Confidence: "HIGH", // Trivy findings are typically high confidence
		File:       target,
		StartLine:  0, // Vulnerabilities don't have line numbers
		Metadata:   metadata,
	}
}

// parseSecret converts a Trivy secret to a RawFinding.
func (p *Parser) parseSecret(target string, secret TrivySecret) ports.RawFinding {
	metadata := map[string]string{
		"type":     "secret",
		"category": secret.Category,
		"target":   target,
	}

	// Extract code snippet (redacted)
	var snippet string
	for _, line := range secret.Code.Lines {
		if line.IsCause {
			snippet = "[REDACTED]" // Never include actual secret content
			break
		}
	}

	return ports.RawFinding{
		RuleID:     secret.RuleID,
		Message:    secret.Title,
		Severity:   secret.Severity,
		Confidence: "HIGH",
		File:       target,
		StartLine:  secret.StartLine,
		EndLine:    secret.EndLine,
		Snippet:    snippet,
		Metadata:   metadata,
	}
}
