// Package vex provides VEX document loading and parsing.
package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	domainvex "github.com/felixgeelhaar/verdictsec/internal/domain/vex"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Loader implements VEX document loading.
type Loader struct{}

// NewLoader creates a new VEX loader.
func NewLoader() *Loader {
	return &Loader{}
}

// LoadFromFile loads a VEX document from a file.
func (l *Loader) LoadFromFile(ctx context.Context, path string) (*domainvex.Document, error) {
	cleanPath, err := pathutil.ValidatePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return l.LoadFromBytes(ctx, data)
}

// LoadFromReader loads a VEX document from a reader.
func (l *Loader) LoadFromReader(ctx context.Context, r io.Reader) (*domainvex.Document, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return l.LoadFromBytes(ctx, data)
}

// LoadFromBytes loads a VEX document from raw bytes.
func (l *Loader) LoadFromBytes(_ context.Context, data []byte) (*domainvex.Document, error) {
	// Try to detect format from content
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("failed to parse VEX JSON: %w", err)
	}

	// Check for OpenVEX format
	if _, hasContext := generic["@context"]; hasContext {
		return l.parseOpenVEX(data)
	}

	// Check for CSAF VEX format
	if _, hasCSAFVersion := generic["csaf_version"]; hasCSAFVersion {
		return l.parseCSAFVEX(data)
	}

	// Default to OpenVEX format
	return l.parseOpenVEX(data)
}

// OpenVEX JSON structure

// OpenVEXDocument represents an OpenVEX JSON document.
type OpenVEXDocument struct {
	Context    string               `json:"@context"`
	ID         string               `json:"@id"`
	Author     string               `json:"author"`
	Timestamp  string               `json:"timestamp"`
	Version    int                  `json:"version"`
	Statements []OpenVEXStatement   `json:"statements"`
}

// OpenVEXStatement represents an OpenVEX statement.
type OpenVEXStatement struct {
	Vulnerability   OpenVEXVulnerability `json:"vulnerability"`
	Products        []OpenVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	Justification   string               `json:"justification,omitempty"`
	ImpactStatement string               `json:"impact_statement,omitempty"`
	ActionStatement string               `json:"action_statement,omitempty"`
	Timestamp       string               `json:"timestamp,omitempty"`
}

// OpenVEXVulnerability represents vulnerability info.
type OpenVEXVulnerability struct {
	ID          string `json:"@id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// OpenVEXProduct represents a product in OpenVEX.
type OpenVEXProduct struct {
	ID            string             `json:"@id"`
	Subcomponents []OpenVEXProduct   `json:"subcomponents,omitempty"`
}

// parseOpenVEX parses OpenVEX JSON format.
func (l *Loader) parseOpenVEX(data []byte) (*domainvex.Document, error) {
	var ovex OpenVEXDocument
	if err := json.Unmarshal(data, &ovex); err != nil {
		return nil, fmt.Errorf("failed to parse OpenVEX: %w", err)
	}

	// Convert statements
	statements := make([]*domainvex.Statement, 0, len(ovex.Statements))
	for _, stmt := range ovex.Statements {
		// Get vulnerability ID
		vulnID := stmt.Vulnerability.ID
		if vulnID == "" {
			vulnID = stmt.Vulnerability.Name
		}

		// Parse status
		status, err := domainvex.ParseStatus(stmt.Status)
		if err != nil {
			// Skip invalid status
			continue
		}

		// Extract product PURLs
		products := make([]string, 0, len(stmt.Products))
		for _, p := range stmt.Products {
			if p.ID != "" {
				products = append(products, p.ID)
			}
		}

		// Create domain statement
		domainStmt := domainvex.NewStatement(
			vulnID,
			status,
			domainvex.Justification(stmt.Justification),
			stmt.ImpactStatement,
			products,
		)

		// Set optional fields
		domainStmt.SetActionStatement(stmt.ActionStatement)

		// Parse timestamp if present
		if stmt.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, stmt.Timestamp); err == nil {
				domainStmt.SetTimestamp(t)
			}
		}

		// Extract subcomponents
		var subcomponents []string
		for _, p := range stmt.Products {
			for _, sc := range p.Subcomponents {
				if sc.ID != "" {
					subcomponents = append(subcomponents, sc.ID)
				}
			}
		}
		if len(subcomponents) > 0 {
			domainStmt.SetSubcomponents(subcomponents)
		}

		statements = append(statements, domainStmt)
	}

	// Create document
	doc := domainvex.NewDocument(ovex.ID, statements)
	doc.SetFormat("openvex")
	doc.SetAuthor(ovex.Author)

	// Parse timestamp
	if ovex.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, ovex.Timestamp); err == nil {
			doc.SetTimestamp(t)
		}
	}

	return doc, nil
}

// CSAF VEX structure (simplified)

// CSAFDocument represents a CSAF VEX document (simplified).
type CSAFDocument struct {
	CSAFVersion string              `json:"csaf_version"`
	Document    CSAFDocumentInfo    `json:"document"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// CSAFDocumentInfo contains document metadata.
type CSAFDocumentInfo struct {
	Title    string           `json:"title"`
	Tracking CSAFTracking     `json:"tracking"`
}

// CSAFTracking contains tracking information.
type CSAFTracking struct {
	ID                 string `json:"id"`
	CurrentReleaseDate string `json:"current_release_date"`
	Generator          struct {
		Engine struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"engine"`
	} `json:"generator"`
}

// CSAFVulnerability represents a CSAF vulnerability.
type CSAFVulnerability struct {
	CVE   string `json:"cve"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags,omitempty"`
	ProductStatus map[string][]string `json:"product_status,omitempty"`
}

// parseCSAFVEX parses CSAF VEX format.
func (l *Loader) parseCSAFVEX(data []byte) (*domainvex.Document, error) {
	var csaf CSAFDocument
	if err := json.Unmarshal(data, &csaf); err != nil {
		return nil, fmt.Errorf("failed to parse CSAF VEX: %w", err)
	}

	// Convert vulnerabilities to statements
	statements := make([]*domainvex.Statement, 0, len(csaf.Vulnerabilities))
	for _, vuln := range csaf.Vulnerabilities {
		if vuln.CVE == "" {
			continue
		}

		// Check product status for not_affected
		if notAffected, ok := vuln.ProductStatus["known_not_affected"]; ok && len(notAffected) > 0 {
			stmt := domainvex.NewStatement(
				vuln.CVE,
				domainvex.StatusNotAffected,
				"", // CSAF doesn't always have justification
				"",
				notAffected,
			)
			statements = append(statements, stmt)
		}

		// Check for fixed
		if fixed, ok := vuln.ProductStatus["fixed"]; ok && len(fixed) > 0 {
			stmt := domainvex.NewStatement(
				vuln.CVE,
				domainvex.StatusFixed,
				"",
				"",
				fixed,
			)
			statements = append(statements, stmt)
		}

		// Check for under investigation
		if investigating, ok := vuln.ProductStatus["under_investigation"]; ok && len(investigating) > 0 {
			stmt := domainvex.NewStatement(
				vuln.CVE,
				domainvex.StatusUnderInvestigation,
				"",
				"",
				investigating,
			)
			statements = append(statements, stmt)
		}
	}

	// Create document
	doc := domainvex.NewDocument(csaf.Document.Tracking.ID, statements)
	doc.SetFormat("csaf")
	doc.SetVersion(csaf.CSAFVersion)

	// Parse timestamp
	if csaf.Document.Tracking.CurrentReleaseDate != "" {
		if t, err := time.Parse(time.RFC3339, csaf.Document.Tracking.CurrentReleaseDate); err == nil {
			doc.SetTimestamp(t)
		}
	}

	return doc, nil
}
