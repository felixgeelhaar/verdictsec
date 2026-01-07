package services

import (
	"encoding/json"
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createScoreFinding(ruleID string, severity finding.Severity, line int) *finding.Finding {
	loc := finding.NewLocation("main.go", line, 1, line, 20)
	return finding.NewFinding(finding.FindingTypeSAST, "gosec", ruleID, "Test", severity, loc)
}

func TestGrade_Description(t *testing.T) {
	tests := []struct {
		grade    Grade
		expected string
	}{
		{GradeA, "Excellent"},
		{GradeB, "Good"},
		{GradeC, "Fair"},
		{GradeD, "Poor"},
		{GradeF, "Critical"},
		{Grade("X"), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.grade), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.grade.Description())
		})
	}
}

func TestScore_String(t *testing.T) {
	score := Score{
		Value: 85,
		Grade: GradeB,
	}

	assert.Equal(t, "85/100 (B)", score.String())
}

func TestScore_MarshalJSON(t *testing.T) {
	score := Score{
		Value: 85,
		Grade: GradeB,
		Factors: []ScoreFactor{
			{Name: "high_findings", Points: -15, Reason: "1 HIGH severity finding(s)"},
		},
	}

	data, err := json.Marshal(score)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, float64(85), result["value"])
	assert.Equal(t, "B", result["grade"])
	assert.Equal(t, "Good", result["description"])
	assert.NotNil(t, result["factors"])
}

func TestNewScoreService(t *testing.T) {
	svc := NewScoreService()
	assert.NotNil(t, svc)
	assert.Equal(t, 25, svc.criticalWeight)
	assert.Equal(t, 15, svc.highWeight)
	assert.Equal(t, 8, svc.mediumWeight)
	assert.Equal(t, 3, svc.lowWeight)
	assert.Equal(t, 1, svc.infoWeight)
}

func TestNewScoreServiceWithConfig(t *testing.T) {
	cfg := ScoreConfig{
		CriticalWeight: 30,
		HighWeight:     20,
		MediumWeight:   10,
		LowWeight:      5,
		InfoWeight:     2,
	}

	svc := NewScoreServiceWithConfig(cfg)
	assert.Equal(t, 30, svc.criticalWeight)
	assert.Equal(t, 20, svc.highWeight)
	assert.Equal(t, 10, svc.mediumWeight)
	assert.Equal(t, 5, svc.lowWeight)
	assert.Equal(t, 2, svc.infoWeight)
}

func TestScoreService_CalculateSimple_NoFindings(t *testing.T) {
	svc := NewScoreService()
	score := svc.CalculateSimple([]*finding.Finding{})

	assert.Equal(t, 100, score.Value)
	assert.Equal(t, GradeA, score.Grade)
	assert.Empty(t, score.Factors)
}

func TestScoreService_CalculateSimple_SingleCritical(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityCritical, 10),
	}

	score := svc.CalculateSimple(findings)

	assert.Equal(t, 75, score.Value) // 100 - 25
	assert.Equal(t, GradeC, score.Grade)
	assert.Len(t, score.Factors, 1)
	assert.Equal(t, "critical_findings", score.Factors[0].Name)
	assert.Equal(t, -25, score.Factors[0].Points)
}

func TestScoreService_CalculateSimple_SingleHigh(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityHigh, 10),
	}

	score := svc.CalculateSimple(findings)

	assert.Equal(t, 85, score.Value) // 100 - 15
	assert.Equal(t, GradeB, score.Grade)
	assert.Len(t, score.Factors, 1)
	assert.Equal(t, "high_findings", score.Factors[0].Name)
	assert.Equal(t, -15, score.Factors[0].Points)
}

func TestScoreService_CalculateSimple_SingleMedium(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityMedium, 10),
	}

	score := svc.CalculateSimple(findings)

	assert.Equal(t, 92, score.Value) // 100 - 8
	assert.Equal(t, GradeA, score.Grade)
}

func TestScoreService_CalculateSimple_SingleLow(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityLow, 10),
	}

	score := svc.CalculateSimple(findings)

	assert.Equal(t, 97, score.Value) // 100 - 3
	assert.Equal(t, GradeA, score.Grade)
}

func TestScoreService_CalculateSimple_SingleInfo(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityInfo, 10),
	}

	score := svc.CalculateSimple(findings)

	assert.Equal(t, 99, score.Value) // 100 - 1
	assert.Equal(t, GradeA, score.Grade)
}

func TestScoreService_CalculateSimple_MixedSeverities(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityCritical, 10),
		createScoreFinding("G402", finding.SeverityHigh, 20),
		createScoreFinding("G403", finding.SeverityMedium, 30),
		createScoreFinding("G404", finding.SeverityLow, 40),
	}

	score := svc.CalculateSimple(findings)

	// 100 - 25 (critical) - 15 (high) - 8 (medium) - 3 (low) = 49
	assert.Equal(t, 49, score.Value)
	assert.Equal(t, GradeF, score.Grade)
	assert.Len(t, score.Factors, 4)
}

func TestScoreService_CalculateSimple_MultipleSameSeverity(t *testing.T) {
	svc := NewScoreService()
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityHigh, 10),
		createScoreFinding("G402", finding.SeverityHigh, 20),
		createScoreFinding("G403", finding.SeverityHigh, 30),
	}

	score := svc.CalculateSimple(findings)

	// 100 - (3 * 15) = 55
	assert.Equal(t, 55, score.Value)
	assert.Equal(t, GradeF, score.Grade)
}

func TestScoreService_CalculateSimple_ClampToZero(t *testing.T) {
	svc := NewScoreService()
	// 5 critical findings = 5 * 25 = 125 points (exceeds 100)
	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityCritical, 10),
		createScoreFinding("G402", finding.SeverityCritical, 20),
		createScoreFinding("G403", finding.SeverityCritical, 30),
		createScoreFinding("G404", finding.SeverityCritical, 40),
		createScoreFinding("G405", finding.SeverityCritical, 50),
	}

	score := svc.CalculateSimple(findings)

	// Should be clamped to 0, not negative
	assert.Equal(t, 0, score.Value)
	assert.Equal(t, GradeF, score.Grade)
}

func TestScoreService_Calculate_WithBaseline(t *testing.T) {
	svc := NewScoreService()
	base := baseline.NewBaseline("./src")

	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityHigh, 10),
	}

	score := svc.Calculate(findings, base, nil)

	// 100 - 15 (high) + 5 (baseline bonus) = 90
	assert.Equal(t, 90, score.Value)
	assert.Equal(t, GradeA, score.Grade)
	assert.Len(t, score.Factors, 2)

	// Check for baseline bonus factor
	hasBaselineBonus := false
	for _, f := range score.Factors {
		if f.Name == "baseline_configured" {
			hasBaselineBonus = true
			assert.Equal(t, 5, f.Points)
		}
	}
	assert.True(t, hasBaselineBonus)
}

func TestScoreService_Calculate_WithResolvedFindings(t *testing.T) {
	svc := NewScoreService()
	base := baseline.NewBaseline("./src")

	// Simulate resolved findings
	diffResult := &DiffResult{
		Resolved: []string{"fingerprint1", "fingerprint2", "fingerprint3"},
	}

	findings := []*finding.Finding{
		createScoreFinding("G401", finding.SeverityMedium, 10),
	}

	score := svc.Calculate(findings, base, diffResult)

	// 100 - 8 (medium) + 5 (baseline) + 3 (resolved, capped) = 100
	assert.Equal(t, 100, score.Value)
	assert.Equal(t, GradeA, score.Grade)

	// Check for resolved bonus factor
	hasResolvedBonus := false
	for _, f := range score.Factors {
		if f.Name == "resolved_findings" {
			hasResolvedBonus = true
			assert.Equal(t, 3, f.Points)
		}
	}
	assert.True(t, hasResolvedBonus)
}

func TestScoreService_Calculate_ResolvedBonusCapped(t *testing.T) {
	svc := NewScoreService()
	base := baseline.NewBaseline("./src")

	// Simulate many resolved findings (more than cap of 10)
	resolved := make([]string, 15)
	for i := 0; i < 15; i++ {
		resolved[i] = "fingerprint" + string(rune('a'+i))
	}
	diffResult := &DiffResult{
		Resolved: resolved,
	}

	score := svc.Calculate([]*finding.Finding{}, base, diffResult)

	// 100 + 5 (baseline) + 10 (resolved, capped at 10) = 115, clamped to 100
	assert.Equal(t, 100, score.Value)

	// Verify resolved bonus is capped
	for _, f := range score.Factors {
		if f.Name == "resolved_findings" {
			assert.Equal(t, 10, f.Points)
			assert.Contains(t, f.Reason, "15 finding(s) resolved")
		}
	}
}

func TestScoreService_CalculateGrade(t *testing.T) {
	svc := NewScoreService()

	tests := []struct {
		value    int
		expected Grade
	}{
		{100, GradeA},
		{95, GradeA},
		{90, GradeA},
		{89, GradeB},
		{85, GradeB},
		{80, GradeB},
		{79, GradeC},
		{75, GradeC},
		{70, GradeC},
		{69, GradeD},
		{65, GradeD},
		{60, GradeD},
		{59, GradeF},
		{50, GradeF},
		{0, GradeF},
	}

	for _, tt := range tests {
		t.Run(string(rune('0'+tt.value/10)), func(t *testing.T) {
			grade := svc.calculateGrade(tt.value)
			assert.Equal(t, tt.expected, grade)
		})
	}
}

func TestScoreService_InfoFindingsCapped(t *testing.T) {
	svc := NewScoreService()

	// 15 info findings should only deduct 10 points (capped)
	findings := make([]*finding.Finding, 15)
	for i := 0; i < 15; i++ {
		findings[i] = createScoreFinding("G"+string(rune('0'+i)), finding.SeverityInfo, i*10)
	}

	score := svc.CalculateSimple(findings)

	// 100 - 10 (capped) = 90
	assert.Equal(t, 90, score.Value)

	// Verify deduction is capped
	for _, f := range score.Factors {
		if f.Name == "info_findings" {
			assert.Equal(t, -10, f.Points)
		}
	}
}
