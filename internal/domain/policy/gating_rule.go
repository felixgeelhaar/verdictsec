package policy

// Mode represents the execution mode (local vs CI).
type Mode string

const (
	ModeLocal Mode = "local"
	ModeCI    Mode = "ci"
)

// GatingRule defines mode-specific threshold overrides.
type GatingRule struct {
	Mode      Mode      `json:"mode" yaml:"mode"`
	Threshold Threshold `json:"threshold" yaml:"threshold"`
}

// Validate checks if the gating rule is valid.
func (g GatingRule) Validate() error {
	if g.Mode != ModeLocal && g.Mode != ModeCI {
		return &ValidationError{Field: "mode", Message: "mode must be 'local' or 'ci'"}
	}
	return g.Threshold.Validate()
}
