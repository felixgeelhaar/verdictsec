package vex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDocument(t *testing.T) {
	statements := []*Statement{
		NewStatement("CVE-2024-1234", StatusNotAffected, "", "", nil),
		NewStatement("CVE-2024-5678", StatusFixed, "", "", nil),
	}

	doc := NewDocument("doc-001", statements)

	assert.Equal(t, "doc-001", doc.ID())
	assert.Equal(t, "openvex", doc.Format())
	assert.Equal(t, "1.0", doc.Version())
	assert.Equal(t, 2, doc.StatementCount())
	assert.Equal(t, statements, doc.Statements())
	assert.NotZero(t, doc.Timestamp())
}

func TestDocument_Setters(t *testing.T) {
	doc := NewDocument("doc-001", nil)

	doc.SetFormat("csaf")
	assert.Equal(t, "csaf", doc.Format())

	doc.SetVersion("2.0")
	assert.Equal(t, "2.0", doc.Version())

	doc.SetAuthor("security-team")
	assert.Equal(t, "security-team", doc.Author())

	now := time.Now()
	doc.SetTimestamp(now)
	assert.Equal(t, now, doc.Timestamp())

	later := now.Add(time.Hour)
	doc.SetLastUpdated(later)
	assert.Equal(t, later, doc.LastUpdated())
}

func TestDocument_FindStatementByVuln(t *testing.T) {
	stmt1 := NewStatement("CVE-2024-1234", StatusNotAffected, "", "", nil)
	stmt2 := NewStatement("CVE-2024-5678", StatusFixed, "", "", nil)
	doc := NewDocument("doc-001", []*Statement{stmt1, stmt2})

	found := doc.FindStatementByVuln("CVE-2024-1234")
	assert.Equal(t, stmt1, found)

	found = doc.FindStatementByVuln("CVE-2024-5678")
	assert.Equal(t, stmt2, found)

	found = doc.FindStatementByVuln("CVE-2024-9999")
	assert.Nil(t, found)
}

func TestDocument_FindStatementsForProduct(t *testing.T) {
	stmt1 := NewStatement("CVE-2024-1234", StatusNotAffected, "", "", []string{"pkg:golang/example.com/foo@v1.0.0"})
	stmt2 := NewStatement("CVE-2024-5678", StatusFixed, "", "", []string{"pkg:golang/example.com/foo@v1.0.0", "pkg:golang/example.com/bar@v1.0.0"})
	stmt3 := NewStatement("CVE-2024-9999", StatusAffected, "", "", []string{"pkg:golang/example.com/baz@v1.0.0"})
	doc := NewDocument("doc-001", []*Statement{stmt1, stmt2, stmt3})

	// Should find 2 statements for foo
	found := doc.FindStatementsForProduct("pkg:golang/example.com/foo@v1.0.0")
	assert.Len(t, found, 2)
	assert.Contains(t, found, stmt1)
	assert.Contains(t, found, stmt2)

	// Should find 1 statement for bar
	found = doc.FindStatementsForProduct("pkg:golang/example.com/bar@v1.0.0")
	assert.Len(t, found, 1)
	assert.Contains(t, found, stmt2)

	// Should find nothing for unknown product
	found = doc.FindStatementsForProduct("pkg:golang/unknown@v1.0.0")
	assert.Len(t, found, 0)
}

func TestDocument_SuppressedVulns(t *testing.T) {
	stmt1 := NewStatement("CVE-2024-1234", StatusNotAffected, "", "", nil)
	stmt2 := NewStatement("CVE-2024-5678", StatusFixed, "", "", nil)
	stmt3 := NewStatement("CVE-2024-9999", StatusAffected, "", "", nil)
	stmt4 := NewStatement("CVE-2024-0000", StatusUnderInvestigation, "", "", nil)
	doc := NewDocument("doc-001", []*Statement{stmt1, stmt2, stmt3, stmt4})

	suppressed := doc.SuppressedVulns()
	assert.Len(t, suppressed, 2)
	assert.Contains(t, suppressed, "CVE-2024-1234")
	assert.Contains(t, suppressed, "CVE-2024-5678")
	assert.NotContains(t, suppressed, "CVE-2024-9999")
	assert.NotContains(t, suppressed, "CVE-2024-0000")
}

func TestDocument_FilteredVulns(t *testing.T) {
	stmt1 := NewStatement("CVE-2024-1234", StatusNotAffected, "", "", nil)
	stmt2 := NewStatement("CVE-2024-5678", StatusFixed, "", "", nil)
	stmt3 := NewStatement("CVE-2024-9999", StatusAffected, "", "", nil)
	stmt4 := NewStatement("CVE-2024-0000", StatusUnderInvestigation, "", "", nil)
	doc := NewDocument("doc-001", []*Statement{stmt1, stmt2, stmt3, stmt4})

	notAffected := doc.NotAffectedVulns()
	assert.Len(t, notAffected, 1)
	assert.Equal(t, stmt1, notAffected[0])

	affected := doc.AffectedVulns()
	assert.Len(t, affected, 1)
	assert.Equal(t, stmt3, affected[0])

	fixed := doc.FixedVulns()
	assert.Len(t, fixed, 1)
	assert.Equal(t, stmt2, fixed[0])
}

func TestDocument_EmptyDocument(t *testing.T) {
	doc := NewDocument("doc-001", nil)

	assert.Equal(t, 0, doc.StatementCount())
	assert.Nil(t, doc.Statements())
	assert.Nil(t, doc.FindStatementByVuln("CVE-2024-1234"))
	assert.Len(t, doc.FindStatementsForProduct("pkg:golang/example.com/foo@v1.0.0"), 0)
	assert.Len(t, doc.SuppressedVulns(), 0)
	assert.Len(t, doc.NotAffectedVulns(), 0)
	assert.Len(t, doc.AffectedVulns(), 0)
	assert.Len(t, doc.FixedVulns(), 0)
}
