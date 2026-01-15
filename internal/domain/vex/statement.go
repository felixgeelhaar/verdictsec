package vex

import (
	"time"
)

// Statement represents a VEX statement about a vulnerability.
// It declares the status of a vulnerability in a specific product.
type Statement struct {
	vulnID        string        // Vulnerability ID (CVE-XXXX-YYYY)
	status        Status        // VEX status
	justification Justification // Justification (required for not_affected)
	impactStatement string      // Explanation of why status was chosen
	actionStatement string      // Actions to take (for affected status)
	products      []string      // Products this statement applies to (PURLs)
	subcomponents []string      // Affected subcomponents
	timestamp     time.Time     // When this statement was made
	author        string        // Who made this statement
	supplier      string        // Supplier/vendor
	version       string        // Version of the product analyzed
}

// NewStatement creates a new VEX statement.
func NewStatement(
	vulnID string,
	status Status,
	justification Justification,
	impactStatement string,
	products []string,
) *Statement {
	return &Statement{
		vulnID:        vulnID,
		status:        status,
		justification: justification,
		impactStatement: impactStatement,
		products:      products,
		timestamp:     time.Now(),
	}
}

// VulnID returns the vulnerability ID.
func (s *Statement) VulnID() string { return s.vulnID }

// Status returns the VEX status.
func (s *Statement) Status() Status { return s.status }

// Justification returns the justification (for not_affected status).
func (s *Statement) Justification() Justification { return s.justification }

// ImpactStatement returns the impact explanation.
func (s *Statement) ImpactStatement() string { return s.impactStatement }

// ActionStatement returns the recommended action (for affected status).
func (s *Statement) ActionStatement() string { return s.actionStatement }

// Products returns the product PURLs this statement applies to.
func (s *Statement) Products() []string { return s.products }

// Subcomponents returns the affected subcomponents.
func (s *Statement) Subcomponents() []string { return s.subcomponents }

// Timestamp returns when this statement was made.
func (s *Statement) Timestamp() time.Time { return s.timestamp }

// Author returns who made this statement.
func (s *Statement) Author() string { return s.author }

// Supplier returns the supplier/vendor.
func (s *Statement) Supplier() string { return s.supplier }

// Version returns the product version analyzed.
func (s *Statement) Version() string { return s.version }

// IsNotAffected returns true if the vulnerability does not affect the product.
func (s *Statement) IsNotAffected() bool {
	return s.status == StatusNotAffected
}

// IsAffected returns true if the vulnerability affects the product.
func (s *Statement) IsAffected() bool {
	return s.status == StatusAffected
}

// IsFixed returns true if the vulnerability has been fixed.
func (s *Statement) IsFixed() bool {
	return s.status == StatusFixed
}

// IsUnderInvestigation returns true if the vulnerability is still being analyzed.
func (s *Statement) IsUnderInvestigation() bool {
	return s.status == StatusUnderInvestigation
}

// ShouldSuppress returns true if this statement indicates the vulnerability
// should be suppressed from reports (not_affected or fixed).
func (s *Statement) ShouldSuppress() bool {
	return s.status == StatusNotAffected || s.status == StatusFixed
}

// AppliesToProduct checks if this statement applies to a given product PURL.
func (s *Statement) AppliesToProduct(purl string) bool {
	for _, p := range s.products {
		if p == purl {
			return true
		}
	}
	return false
}

// SetTimestamp sets the statement timestamp.
func (s *Statement) SetTimestamp(t time.Time) {
	s.timestamp = t
}

// SetAuthor sets the statement author.
func (s *Statement) SetAuthor(author string) {
	s.author = author
}

// SetSupplier sets the supplier.
func (s *Statement) SetSupplier(supplier string) {
	s.supplier = supplier
}

// SetVersion sets the version.
func (s *Statement) SetVersion(version string) {
	s.version = version
}

// SetActionStatement sets the action statement.
func (s *Statement) SetActionStatement(action string) {
	s.actionStatement = action
}

// SetSubcomponents sets the subcomponents.
func (s *Statement) SetSubcomponents(subcomponents []string) {
	s.subcomponents = subcomponents
}
