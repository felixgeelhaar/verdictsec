package baseline

// Scope defines what the baseline covers.
type Scope struct {
	Target    string   `json:"target"`
	EngineIDs []string `json:"engine_ids,omitempty"`
}

// NewScope creates a new scope for a target.
func NewScope(target string, engineIDs ...string) Scope {
	return Scope{
		Target:    target,
		EngineIDs: engineIDs,
	}
}

// Matches returns true if the scope matches the given target and engine.
func (s Scope) Matches(target, engineID string) bool {
	if s.Target != target {
		return false
	}
	if len(s.EngineIDs) == 0 {
		return true // No engine filter means all engines
	}
	for _, id := range s.EngineIDs {
		if id == engineID {
			return true
		}
	}
	return false
}

// MatchesTarget returns true if the scope matches the target (ignoring engine filter).
func (s Scope) MatchesTarget(target string) bool {
	return s.Target == target
}

// HasEngineFilter returns true if the scope has an engine filter.
func (s Scope) HasEngineFilter() bool {
	return len(s.EngineIDs) > 0
}

// ContainsEngine returns true if the engine is in the scope's engine list.
func (s Scope) ContainsEngine(engineID string) bool {
	if len(s.EngineIDs) == 0 {
		return true
	}
	for _, id := range s.EngineIDs {
		if id == engineID {
			return true
		}
	}
	return false
}
