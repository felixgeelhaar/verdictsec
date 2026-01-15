package vex

import (
	"time"
)

// Document represents a VEX document containing multiple statements.
type Document struct {
	id          string       // Document identifier
	format      string       // Document format (openvex, csaf, etc.)
	version     string       // VEX specification version
	author      string       // Document author
	timestamp   time.Time    // Document creation time
	lastUpdated time.Time    // Last update time
	statements  []*Statement // VEX statements
}

// NewDocument creates a new VEX document.
func NewDocument(id string, statements []*Statement) *Document {
	return &Document{
		id:         id,
		format:     "openvex",
		version:    "1.0",
		timestamp:  time.Now(),
		statements: statements,
	}
}

// ID returns the document ID.
func (d *Document) ID() string { return d.id }

// Format returns the document format.
func (d *Document) Format() string { return d.format }

// Version returns the VEX specification version.
func (d *Document) Version() string { return d.version }

// Author returns the document author.
func (d *Document) Author() string { return d.author }

// Timestamp returns the document creation time.
func (d *Document) Timestamp() time.Time { return d.timestamp }

// LastUpdated returns the last update time.
func (d *Document) LastUpdated() time.Time { return d.lastUpdated }

// Statements returns all VEX statements.
func (d *Document) Statements() []*Statement { return d.statements }

// StatementCount returns the number of statements.
func (d *Document) StatementCount() int { return len(d.statements) }

// SetFormat sets the document format.
func (d *Document) SetFormat(format string) {
	d.format = format
}

// SetVersion sets the VEX spec version.
func (d *Document) SetVersion(version string) {
	d.version = version
}

// SetAuthor sets the document author.
func (d *Document) SetAuthor(author string) {
	d.author = author
}

// SetTimestamp sets the document timestamp.
func (d *Document) SetTimestamp(t time.Time) {
	d.timestamp = t
}

// SetLastUpdated sets the last updated time.
func (d *Document) SetLastUpdated(t time.Time) {
	d.lastUpdated = t
}

// FindStatementByVuln returns the statement for a given vulnerability ID.
func (d *Document) FindStatementByVuln(vulnID string) *Statement {
	for _, s := range d.statements {
		if s.VulnID() == vulnID {
			return s
		}
	}
	return nil
}

// FindStatementsForProduct returns all statements affecting a product.
func (d *Document) FindStatementsForProduct(purl string) []*Statement {
	var result []*Statement
	for _, s := range d.statements {
		if s.AppliesToProduct(purl) {
			result = append(result, s)
		}
	}
	return result
}

// SuppressedVulns returns a map of vulnerability IDs that should be suppressed.
// These are vulnerabilities marked as not_affected or fixed.
func (d *Document) SuppressedVulns() map[string]*Statement {
	result := make(map[string]*Statement)
	for _, s := range d.statements {
		if s.ShouldSuppress() {
			result[s.VulnID()] = s
		}
	}
	return result
}

// NotAffectedVulns returns vulnerabilities marked as not_affected.
func (d *Document) NotAffectedVulns() []*Statement {
	var result []*Statement
	for _, s := range d.statements {
		if s.IsNotAffected() {
			result = append(result, s)
		}
	}
	return result
}

// AffectedVulns returns vulnerabilities marked as affected.
func (d *Document) AffectedVulns() []*Statement {
	var result []*Statement
	for _, s := range d.statements {
		if s.IsAffected() {
			result = append(result, s)
		}
	}
	return result
}

// FixedVulns returns vulnerabilities marked as fixed.
func (d *Document) FixedVulns() []*Statement {
	var result []*Statement
	for _, s := range d.statements {
		if s.IsFixed() {
			result = append(result, s)
		}
	}
	return result
}
