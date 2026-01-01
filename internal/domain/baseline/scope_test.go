package baseline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewScope(t *testing.T) {
	// Without engine filter
	scope := NewScope("./src")
	assert.Equal(t, "./src", scope.Target)
	assert.Empty(t, scope.EngineIDs)

	// With engine filter
	scope = NewScope("./src", "gosec", "govulncheck")
	assert.Equal(t, "./src", scope.Target)
	assert.Equal(t, []string{"gosec", "govulncheck"}, scope.EngineIDs)
}

func TestScope_Matches(t *testing.T) {
	tests := []struct {
		name      string
		scope     Scope
		target    string
		engineID  string
		expectRes bool
	}{
		{
			name:      "matches target without engine filter",
			scope:     NewScope("./src"),
			target:    "./src",
			engineID:  "gosec",
			expectRes: true,
		},
		{
			name:      "matches target and engine",
			scope:     NewScope("./src", "gosec", "govulncheck"),
			target:    "./src",
			engineID:  "gosec",
			expectRes: true,
		},
		{
			name:      "does not match wrong target",
			scope:     NewScope("./src"),
			target:    "./other",
			engineID:  "gosec",
			expectRes: false,
		},
		{
			name:      "does not match wrong engine",
			scope:     NewScope("./src", "gosec"),
			target:    "./src",
			engineID:  "govulncheck",
			expectRes: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.Matches(tt.target, tt.engineID)
			assert.Equal(t, tt.expectRes, result)
		})
	}
}

func TestScope_MatchesTarget(t *testing.T) {
	scope := NewScope("./src", "gosec")

	assert.True(t, scope.MatchesTarget("./src"))
	assert.False(t, scope.MatchesTarget("./other"))
}

func TestScope_HasEngineFilter(t *testing.T) {
	scopeWithFilter := NewScope("./src", "gosec")
	scopeWithoutFilter := NewScope("./src")

	assert.True(t, scopeWithFilter.HasEngineFilter())
	assert.False(t, scopeWithoutFilter.HasEngineFilter())
}

func TestScope_ContainsEngine(t *testing.T) {
	scopeWithFilter := NewScope("./src", "gosec", "govulncheck")
	scopeWithoutFilter := NewScope("./src")

	// With filter
	assert.True(t, scopeWithFilter.ContainsEngine("gosec"))
	assert.True(t, scopeWithFilter.ContainsEngine("govulncheck"))
	assert.False(t, scopeWithFilter.ContainsEngine("gitleaks"))

	// Without filter - all engines match
	assert.True(t, scopeWithoutFilter.ContainsEngine("gosec"))
	assert.True(t, scopeWithoutFilter.ContainsEngine("anything"))
}
