package assessment

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// Metadata contains versioning and traceability information.
type Metadata struct {
	NormalizationVersion string `json:"normalization_version"`
	FingerprintVersion   string `json:"fingerprint_version"`
	PolicyVersion        string `json:"policy_version,omitempty"`
	ToolVersion          string `json:"tool_version,omitempty"`
}

// Assessment is the aggregate root for a security scan.
// It is immutable after completion, ensuring deterministic behavior.
type Assessment struct {
	id          string
	target      string
	startedAt   time.Time
	completedAt time.Time
	engineRuns  []*EngineRun
	findings    []*finding.Finding
	decision    Decision
	reasons     []string
	metadata    Metadata
}

// NewAssessment creates a new assessment for the given target.
func NewAssessment(target string) *Assessment {
	return &Assessment{
		id:         generateAssessmentID(),
		target:     target,
		startedAt:  time.Now().UTC(),
		engineRuns: make([]*EngineRun, 0),
		findings:   make([]*finding.Finding, 0),
		decision:   DecisionUnknown,
		reasons:    make([]string, 0),
		metadata: Metadata{
			NormalizationVersion: "v1",
			FingerprintVersion:   finding.FingerprintVersion,
		},
	}
}

// ID returns the unique identifier for this assessment.
func (a *Assessment) ID() string { return a.id }

// Target returns the scan target path.
func (a *Assessment) Target() string { return a.target }

// StartedAt returns when the assessment started.
func (a *Assessment) StartedAt() time.Time { return a.startedAt }

// CompletedAt returns when the assessment completed.
func (a *Assessment) CompletedAt() time.Time { return a.completedAt }

// EngineRuns returns all engine runs in this assessment.
func (a *Assessment) EngineRuns() []*EngineRun { return a.engineRuns }

// Findings returns all findings in this assessment.
func (a *Assessment) Findings() []*finding.Finding { return a.findings }

// Decision returns the final decision.
func (a *Assessment) Decision() Decision { return a.decision }

// Reasons returns the reasons for the decision.
func (a *Assessment) Reasons() []string { return a.reasons }

// Metadata returns the assessment metadata.
func (a *Assessment) Metadata() Metadata { return a.metadata }

// IsCompleted returns true if the assessment has been completed.
func (a *Assessment) IsCompleted() bool { return !a.completedAt.IsZero() }

// Duration returns the total duration of the assessment.
func (a *Assessment) Duration() time.Duration {
	if a.completedAt.IsZero() {
		return time.Since(a.startedAt)
	}
	return a.completedAt.Sub(a.startedAt)
}

// AddEngineRun records an engine execution.
func (a *Assessment) AddEngineRun(run *EngineRun) {
	a.engineRuns = append(a.engineRuns, run)
}

// AddFinding adds a normalized finding.
func (a *Assessment) AddFinding(f *finding.Finding) {
	a.findings = append(a.findings, f)
}

// AddFindings adds multiple findings.
func (a *Assessment) AddFindings(findings []*finding.Finding) {
	a.findings = append(a.findings, findings...)
}

// SetDecision sets the final decision with reasons.
func (a *Assessment) SetDecision(decision Decision, reasons []string) {
	a.decision = decision
	a.reasons = reasons
}

// Complete marks the assessment as finished.
func (a *Assessment) Complete() {
	a.completedAt = time.Now().UTC()
}

// SetPolicyVersion records the policy version used.
func (a *Assessment) SetPolicyVersion(version string) {
	a.metadata.PolicyVersion = version
}

// SetToolVersion records the tool version.
func (a *Assessment) SetToolVersion(version string) {
	a.metadata.ToolVersion = version
}

// FindingsByType filters findings by type.
func (a *Assessment) FindingsByType(t finding.FindingType) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range a.findings {
		if f.Type() == t {
			result = append(result, f)
		}
	}
	return result
}

// FindingsBySeverity filters findings at or above a severity.
func (a *Assessment) FindingsBySeverity(minSeverity finding.Severity) []*finding.Finding {
	var result []*finding.Finding
	for _, f := range a.findings {
		if f.EffectiveSeverity().IsAtLeast(minSeverity) {
			result = append(result, f)
		}
	}
	return result
}

// FindingCount returns the total number of findings.
func (a *Assessment) FindingCount() int {
	return len(a.findings)
}

// Summary returns counts by severity.
func (a *Assessment) Summary() map[finding.Severity]int {
	summary := make(map[finding.Severity]int)
	for _, f := range a.findings {
		summary[f.EffectiveSeverity()]++
	}
	return summary
}

// SuccessfulEngineRuns returns the count of successful engine runs.
func (a *Assessment) SuccessfulEngineRuns() int {
	count := 0
	for _, run := range a.engineRuns {
		if run.Success() {
			count++
		}
	}
	return count
}

// FailedEngineRuns returns the count of failed engine runs.
func (a *Assessment) FailedEngineRuns() int {
	count := 0
	for _, run := range a.engineRuns {
		if !run.Success() {
			count++
		}
	}
	return count
}

func generateAssessmentID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "assessment-" + time.Now().UTC().Format("20060102150405")
	}
	return "assessment-" + hex.EncodeToString(b)
}

// AssessmentData is the serializable representation of an Assessment.
type AssessmentData struct {
	ID          string              `json:"id"`
	Target      string              `json:"target"`
	StartedAt   time.Time           `json:"started_at"`
	CompletedAt time.Time           `json:"completed_at"`
	EngineRuns  []EngineRunData     `json:"engine_runs"`
	Findings    []*finding.Finding  `json:"findings"`
	Decision    Decision            `json:"decision"`
	Reasons     []string            `json:"reasons"`
	Metadata    Metadata            `json:"metadata"`
	Summary     map[string]int      `json:"summary"`
}

// MarshalJSON implements json.Marshaler.
func (a *Assessment) MarshalJSON() ([]byte, error) {
	engineRuns := make([]EngineRunData, len(a.engineRuns))
	for i, run := range a.engineRuns {
		engineRuns[i] = run.ToData()
	}

	// Convert summary keys to strings for JSON
	summary := make(map[string]int)
	for sev, count := range a.Summary() {
		summary[sev.String()] = count
	}

	return json.Marshal(AssessmentData{
		ID:          a.id,
		Target:      a.target,
		StartedAt:   a.startedAt,
		CompletedAt: a.completedAt,
		EngineRuns:  engineRuns,
		Findings:    a.findings,
		Decision:    a.decision,
		Reasons:     a.reasons,
		Metadata:    a.metadata,
		Summary:     summary,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *Assessment) UnmarshalJSON(data []byte) error {
	var ad AssessmentData
	if err := json.Unmarshal(data, &ad); err != nil {
		return err
	}

	a.id = ad.ID
	a.target = ad.Target
	a.startedAt = ad.StartedAt
	a.completedAt = ad.CompletedAt
	a.decision = ad.Decision
	a.reasons = ad.Reasons
	a.metadata = ad.Metadata
	a.findings = ad.Findings

	a.engineRuns = make([]*EngineRun, len(ad.EngineRuns))
	for i, runData := range ad.EngineRuns {
		a.engineRuns[i] = EngineRunFromData(runData)
	}

	if a.reasons == nil {
		a.reasons = make([]string, 0)
	}
	if a.findings == nil {
		a.findings = make([]*finding.Finding, 0)
	}
	if a.engineRuns == nil {
		a.engineRuns = make([]*EngineRun, 0)
	}

	return nil
}
