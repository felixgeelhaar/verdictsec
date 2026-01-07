package advisory

import (
	"encoding/json"
	"time"
)

// Explanation is a value object representing an AI-generated explanation
// of a security finding. It is immutable and marked as advisory-only.
type Explanation struct {
	findingID   string
	summary     string
	details     string
	riskContext string
	references  []string
	provider    string
	model       string
	generatedAt time.Time
}

// ExplanationOption is a functional option for creating explanations.
type ExplanationOption func(*Explanation)

// NewExplanation creates a new explanation for a finding.
func NewExplanation(
	findingID string,
	summary string,
	provider string,
	model string,
	opts ...ExplanationOption,
) *Explanation {
	e := &Explanation{
		findingID:   findingID,
		summary:     summary,
		provider:    provider,
		model:       model,
		generatedAt: time.Now().UTC(),
		references:  make([]string, 0),
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Functional options for explanation creation

// WithDetails sets the detailed explanation.
func WithDetails(details string) ExplanationOption {
	return func(e *Explanation) { e.details = details }
}

// WithRiskContext sets the risk context for the finding.
func WithRiskContext(context string) ExplanationOption {
	return func(e *Explanation) { e.riskContext = context }
}

// WithReferences sets the reference URLs for further reading.
func WithReferences(refs []string) ExplanationOption {
	return func(e *Explanation) { e.references = refs }
}

// Getters - provide immutable access to explanation fields

// FindingID returns the ID of the finding this explanation is for.
func (e *Explanation) FindingID() string { return e.findingID }

// Summary returns a brief summary of the finding.
func (e *Explanation) Summary() string { return e.summary }

// Details returns detailed explanation of the finding.
func (e *Explanation) Details() string { return e.details }

// RiskContext returns contextual risk information.
func (e *Explanation) RiskContext() string { return e.riskContext }

// References returns external reference URLs.
func (e *Explanation) References() []string { return e.references }

// Provider returns the AI provider that generated this explanation.
func (e *Explanation) Provider() string { return e.provider }

// Model returns the model ID used to generate this explanation.
func (e *Explanation) Model() string { return e.model }

// GeneratedAt returns when this explanation was generated.
func (e *Explanation) GeneratedAt() time.Time { return e.generatedAt }

// IsAdvisory always returns true - explanations are advisory only.
func (e *Explanation) IsAdvisory() bool { return true }

// explanationJSON is the JSON representation of an explanation.
type explanationJSON struct {
	FindingID   string    `json:"finding_id"`
	Summary     string    `json:"summary"`
	Details     string    `json:"details,omitempty"`
	RiskContext string    `json:"risk_context,omitempty"`
	References  []string  `json:"references,omitempty"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model"`
	GeneratedAt time.Time `json:"generated_at"`
	Advisory    bool      `json:"advisory"`
}

// MarshalJSON implements json.Marshaler.
func (e *Explanation) MarshalJSON() ([]byte, error) {
	return json.Marshal(explanationJSON{
		FindingID:   e.findingID,
		Summary:     e.summary,
		Details:     e.details,
		RiskContext: e.riskContext,
		References:  e.references,
		Provider:    e.provider,
		Model:       e.model,
		GeneratedAt: e.generatedAt,
		Advisory:    true,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (e *Explanation) UnmarshalJSON(data []byte) error {
	var ej explanationJSON
	if err := json.Unmarshal(data, &ej); err != nil {
		return err
	}

	e.findingID = ej.FindingID
	e.summary = ej.Summary
	e.details = ej.Details
	e.riskContext = ej.RiskContext
	e.references = ej.References
	e.provider = ej.Provider
	e.model = ej.Model
	e.generatedAt = ej.GeneratedAt

	if e.references == nil {
		e.references = make([]string, 0)
	}

	return nil
}
