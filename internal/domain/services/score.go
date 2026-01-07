package services

import (
	"encoding/json"
	"fmt"

	"github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Grade represents a letter grade for security posture.
type Grade string

const (
	GradeA Grade = "A" // 90-100: Excellent
	GradeB Grade = "B" // 80-89: Good
	GradeC Grade = "C" // 70-79: Fair
	GradeD Grade = "D" // 60-69: Poor
	GradeF Grade = "F" // 0-59: Critical
)

// Description returns a human-readable description of the grade.
func (g Grade) Description() string {
	switch g {
	case GradeA:
		return "Excellent"
	case GradeB:
		return "Good"
	case GradeC:
		return "Fair"
	case GradeD:
		return "Poor"
	case GradeF:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ScoreFactor represents a factor that affects the security score.
type ScoreFactor struct {
	Name   string `json:"name"`
	Points int    `json:"points"` // Positive = bonus, negative = deduction
	Reason string `json:"reason"`
}

// Score represents a security score with breakdown.
type Score struct {
	Value   int           `json:"value"`   // 0-100
	Grade   Grade         `json:"grade"`   // A, B, C, D, F
	Factors []ScoreFactor `json:"factors"` // Breakdown of score
}

// String returns a human-readable representation of the score.
func (s Score) String() string {
	return fmt.Sprintf("%d/100 (%s)", s.Value, s.Grade)
}

// MarshalJSON implements json.Marshaler.
func (s Score) MarshalJSON() ([]byte, error) {
	type alias Score
	return json.Marshal(struct {
		alias
		Description string `json:"description"`
	}{
		alias:       alias(s),
		Description: s.Grade.Description(),
	})
}

// ScoreService calculates security scores from findings.
// It is a domain service that provides an at-a-glance security posture indicator.
type ScoreService struct {
	// Severity weights (points deducted per finding)
	criticalWeight int
	highWeight     int
	mediumWeight   int
	lowWeight      int
	infoWeight     int

	// Caps (maximum deductions per severity)
	criticalCap int
	highCap     int
	mediumCap   int
	lowCap      int
}

// NewScoreService creates a new score service with default weights.
func NewScoreService() *ScoreService {
	return &ScoreService{
		criticalWeight: 25,
		highWeight:     15,
		mediumWeight:   8,
		lowWeight:      3,
		infoWeight:     1,

		criticalCap: 100, // 4 critical findings max out
		highCap:     100, // 7 high findings max out
		mediumCap:   100, // 13 medium findings max out
		lowCap:      100, // 34 low findings max out
	}
}

// Calculate computes a security score from findings.
// Optionally considers baseline for bonus points.
func (s *ScoreService) Calculate(
	findings []*finding.Finding,
	base *baseline.Baseline,
	diffResult *DiffResult,
) Score {
	score := Score{
		Value:   100,
		Factors: []ScoreFactor{},
	}

	// Count findings by severity
	counts := s.countBySeverity(findings)

	// Apply severity deductions
	s.applySeverityDeductions(&score, counts)

	// Apply baseline bonuses
	if base != nil {
		s.applyBaselineBonus(&score, base, diffResult)
	}

	// Clamp score to 0-100
	if score.Value < 0 {
		score.Value = 0
	}
	if score.Value > 100 {
		score.Value = 100
	}

	// Calculate grade
	score.Grade = s.calculateGrade(score.Value)

	return score
}

// CalculateSimple computes a score without baseline consideration.
func (s *ScoreService) CalculateSimple(findings []*finding.Finding) Score {
	return s.Calculate(findings, nil, nil)
}

// countBySeverity counts findings by severity level.
func (s *ScoreService) countBySeverity(findings []*finding.Finding) map[finding.Severity]int {
	counts := make(map[finding.Severity]int)
	for _, f := range findings {
		counts[f.NormalizedSeverity()]++
	}
	return counts
}

// applySeverityDeductions applies point deductions based on finding severities.
func (s *ScoreService) applySeverityDeductions(score *Score, counts map[finding.Severity]int) {
	// Critical findings
	if count := counts[finding.SeverityCritical]; count > 0 {
		deduction := min(count*s.criticalWeight, s.criticalCap)
		score.Value -= deduction
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "critical_findings",
			Points: -deduction,
			Reason: fmt.Sprintf("%d CRITICAL severity finding(s)", count),
		})
	}

	// High findings
	if count := counts[finding.SeverityHigh]; count > 0 {
		deduction := min(count*s.highWeight, s.highCap)
		score.Value -= deduction
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "high_findings",
			Points: -deduction,
			Reason: fmt.Sprintf("%d HIGH severity finding(s)", count),
		})
	}

	// Medium findings
	if count := counts[finding.SeverityMedium]; count > 0 {
		deduction := min(count*s.mediumWeight, s.mediumCap)
		score.Value -= deduction
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "medium_findings",
			Points: -deduction,
			Reason: fmt.Sprintf("%d MEDIUM severity finding(s)", count),
		})
	}

	// Low findings
	if count := counts[finding.SeverityLow]; count > 0 {
		deduction := min(count*s.lowWeight, s.lowCap)
		score.Value -= deduction
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "low_findings",
			Points: -deduction,
			Reason: fmt.Sprintf("%d LOW severity finding(s)", count),
		})
	}

	// Info findings (minimal impact)
	if count := counts[finding.SeverityInfo]; count > 0 {
		deduction := min(count*s.infoWeight, 10) // Cap at 10 points
		score.Value -= deduction
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "info_findings",
			Points: -deduction,
			Reason: fmt.Sprintf("%d INFO severity finding(s)", count),
		})
	}
}

// applyBaselineBonus adds bonus points for baseline usage and resolved findings.
func (s *ScoreService) applyBaselineBonus(score *Score, base *baseline.Baseline, diffResult *DiffResult) {
	// Bonus for having a baseline configured
	score.Value += 5
	score.Factors = append(score.Factors, ScoreFactor{
		Name:   "baseline_configured",
		Points: 5,
		Reason: "Baseline configured for tracking",
	})

	// Bonus for resolved findings (findings that were in baseline but are now fixed)
	if diffResult != nil && len(diffResult.Resolved) > 0 {
		resolvedBonus := min(len(diffResult.Resolved), 10) // Cap at 10 points
		score.Value += resolvedBonus
		score.Factors = append(score.Factors, ScoreFactor{
			Name:   "resolved_findings",
			Points: resolvedBonus,
			Reason: fmt.Sprintf("%d finding(s) resolved since baseline", len(diffResult.Resolved)),
		})
	}
}

// calculateGrade converts a numeric score to a letter grade.
func (s *ScoreService) calculateGrade(value int) Grade {
	switch {
	case value >= 90:
		return GradeA
	case value >= 80:
		return GradeB
	case value >= 70:
		return GradeC
	case value >= 60:
		return GradeD
	default:
		return GradeF
	}
}

// ScoreConfig allows customizing the score calculation.
type ScoreConfig struct {
	CriticalWeight int `yaml:"critical_weight" json:"critical_weight"`
	HighWeight     int `yaml:"high_weight" json:"high_weight"`
	MediumWeight   int `yaml:"medium_weight" json:"medium_weight"`
	LowWeight      int `yaml:"low_weight" json:"low_weight"`
	InfoWeight     int `yaml:"info_weight" json:"info_weight"`
}

// WithConfig creates a score service with custom weights.
func NewScoreServiceWithConfig(cfg ScoreConfig) *ScoreService {
	s := NewScoreService()
	if cfg.CriticalWeight > 0 {
		s.criticalWeight = cfg.CriticalWeight
	}
	if cfg.HighWeight > 0 {
		s.highWeight = cfg.HighWeight
	}
	if cfg.MediumWeight > 0 {
		s.mediumWeight = cfg.MediumWeight
	}
	if cfg.LowWeight > 0 {
		s.lowWeight = cfg.LowWeight
	}
	if cfg.InfoWeight > 0 {
		s.infoWeight = cfg.InfoWeight
	}
	return s
}
