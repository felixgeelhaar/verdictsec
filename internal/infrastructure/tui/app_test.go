package tui

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	// Create a test assessment
	assess := assessment.NewAssessment("./test")
	f1 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Hardcoded secret",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)
	assess.AddFinding(f1)

	// Create eval result
	evalResult := services.EvaluationResult{
		Decision:    assessment.DecisionWarn,
		NewFindings: []*finding.Finding{f1},
		Existing:    []*finding.Finding{},
		Suppressed:  []*finding.Finding{},
	}

	// Create model
	model := New(assess, evalResult, nil, "", true)

	// Verify model is initialized correctly
	assert.NotNil(t, model.assessment)
	assert.NotNil(t, model.findingList)
	assert.NotNil(t, model.detailViewport)
	assert.NotNil(t, model.searchInput)
	assert.NotNil(t, model.baselineInput)
	assert.Equal(t, ViewModeList, model.viewMode)
	assert.Equal(t, 1, len(model.allFindings))
	assert.Equal(t, "new", model.allFindings[0].Status)
}

func TestNew_WithBaseline(t *testing.T) {
	// Create a test assessment with two findings
	assess := assessment.NewAssessment("./test")
	f1 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Hardcoded secret",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)
	f2 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G102",
		"SQL Injection",
		finding.SeverityCritical,
		finding.NewLocation("db.go", 20, 1, 20, 50),
	)
	assess.AddFinding(f1)
	assess.AddFinding(f2)

	// Create baseline
	baseline := domainBaseline.NewBaseline("./test")
	_ = baseline.Add(f1, "Accepted risk")

	// Create eval result
	evalResult := services.EvaluationResult{
		Decision:    assessment.DecisionFail,
		NewFindings: []*finding.Finding{f2},
		Existing:    []*finding.Finding{f1},
		Suppressed:  []*finding.Finding{},
	}

	// Create model
	model := New(assess, evalResult, baseline, ".verdict/baseline.json", true)

	// Verify findings are categorized correctly
	assert.Equal(t, 2, len(model.allFindings))

	// Find the baselined finding
	var found bool
	for _, item := range model.allFindings {
		if item.Finding.RuleID() == "G101" {
			assert.Equal(t, "baseline", item.Status)
			found = true
		}
	}
	assert.True(t, found, "Should find baselined finding")
}

func TestCategorizeFindings(t *testing.T) {
	f1 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"New finding",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)
	f2 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G102",
		"Existing finding",
		finding.SeverityMedium,
		finding.NewLocation("db.go", 20, 1, 20, 50),
	)
	f3 := finding.NewFinding(
		finding.FindingTypeSecret,
		"gitleaks",
		"aws-key",
		"Suppressed finding",
		finding.SeverityCritical,
		finding.NewLocation("config.go", 30, 1, 30, 50),
	)

	findings := []*finding.Finding{f1, f2, f3}
	evalResult := services.EvaluationResult{
		NewFindings: []*finding.Finding{f1},
		Existing:    []*finding.Finding{f2},
		Suppressed:  []*finding.Finding{f3},
	}

	items := categorizeFindings(findings, evalResult)

	assert.Equal(t, 3, len(items))

	// Verify statuses
	statusMap := make(map[string]string)
	for _, item := range items {
		statusMap[item.Finding.RuleID()] = item.Status
	}

	assert.Equal(t, "new", statusMap["G101"])
	assert.Equal(t, "baseline", statusMap["G102"])
	assert.Equal(t, "suppressed", statusMap["aws-key"])
}

func TestNew_FilterStateInitialization(t *testing.T) {
	assess := assessment.NewAssessment("./test")
	f1 := finding.NewFinding(
		finding.FindingTypeSAST,
		"gosec",
		"G101",
		"Test finding",
		finding.SeverityHigh,
		finding.NewLocation("main.go", 10, 1, 10, 50),
	)
	assess.AddFinding(f1)

	evalResult := services.EvaluationResult{
		Decision:    assessment.DecisionPass,
		NewFindings: []*finding.Finding{f1},
	}

	model := New(assess, evalResult, nil, "", true)

	// Verify all severities are enabled by default
	assert.True(t, model.filterState.Severities[finding.SeverityCritical])
	assert.True(t, model.filterState.Severities[finding.SeverityHigh])
	assert.True(t, model.filterState.Severities[finding.SeverityMedium])
	assert.True(t, model.filterState.Severities[finding.SeverityLow])

	// Verify status filter is set to show all
	assert.Equal(t, StatusAll, model.filterState.Status)

	// Verify engines are enabled
	assert.True(t, model.filterState.Engines["gosec"])
}
