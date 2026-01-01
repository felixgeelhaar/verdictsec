package assessment

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewEngineRun(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")

	assert.Equal(t, "gosec", run.EngineID())
	assert.Equal(t, "2.18.0", run.EngineVersion())
	assert.False(t, run.StartedAt().IsZero())
	assert.True(t, run.CompletedAt().IsZero())
	assert.False(t, run.Success())
	assert.Equal(t, 0, run.FindingCount())
}

func TestEngineRun_Complete(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")
	time.Sleep(10 * time.Millisecond)

	run.Complete(5)

	assert.True(t, run.Success())
	assert.Equal(t, 5, run.FindingCount())
	assert.False(t, run.CompletedAt().IsZero())
	assert.Greater(t, run.Duration(), time.Duration(0))
	assert.Empty(t, run.ErrorMessage())
}

func TestEngineRun_Fail(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")

	run.Fail(errors.New("engine crashed"))

	assert.False(t, run.Success())
	assert.Equal(t, "engine crashed", run.ErrorMessage())
	assert.False(t, run.CompletedAt().IsZero())
}

func TestEngineRun_FailNilError(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")

	run.Fail(nil)

	assert.False(t, run.Success())
	assert.Empty(t, run.ErrorMessage())
}

func TestEngineRun_Duration(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")

	// Not completed yet
	assert.Equal(t, time.Duration(0), run.Duration())

	time.Sleep(10 * time.Millisecond)
	run.Complete(0)

	assert.Greater(t, run.Duration(), 10*time.Millisecond)
}

func TestEngineRun_ToData(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")
	run.Complete(3)

	data := run.ToData()

	assert.Equal(t, "gosec", data.EngineID)
	assert.Equal(t, "2.18.0", data.EngineVersion)
	assert.True(t, data.Success)
	assert.Equal(t, 3, data.FindingCount)
}

func TestEngineRunFromData(t *testing.T) {
	data := EngineRunData{
		EngineID:      "gosec",
		EngineVersion: "2.18.0",
		StartedAt:     time.Now().UTC(),
		CompletedAt:   time.Now().UTC(),
		Success:       true,
		FindingCount:  5,
	}

	run := EngineRunFromData(data)

	assert.Equal(t, "gosec", run.EngineID())
	assert.Equal(t, "2.18.0", run.EngineVersion())
	assert.True(t, run.Success())
	assert.Equal(t, 5, run.FindingCount())
}

func TestEngineRun_SetEvidence(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")
	rawOutput := []byte(`{"Issues": []}`)
	format := "json"

	run.SetEvidence(rawOutput, format)

	assert.Equal(t, rawOutput, run.RawOutput())
	assert.Equal(t, format, run.OutputFormat())
}

func TestEngineRun_RawOutput_Empty(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")

	// Initially nil
	assert.Nil(t, run.RawOutput())
	assert.Empty(t, run.OutputFormat())
}

func TestEngineRun_SetEvidence_LargeOutput(t *testing.T) {
	run := NewEngineRun("gosec", "2.18.0")
	// Simulate large output
	largeOutput := make([]byte, 10000)
	for i := range largeOutput {
		largeOutput[i] = 'x'
	}

	run.SetEvidence(largeOutput, "sarif")

	assert.Equal(t, largeOutput, run.RawOutput())
	assert.Equal(t, "sarif", run.OutputFormat())
	assert.Len(t, run.RawOutput(), 10000)
}

func TestEngineRunFromData_WithEvidence(t *testing.T) {
	data := EngineRunData{
		EngineID:      "gosec",
		EngineVersion: "2.18.0",
		StartedAt:     time.Now().UTC(),
		CompletedAt:   time.Now().UTC(),
		Success:       true,
		FindingCount:  5,
		OutputFormat:  "json",
	}

	run := EngineRunFromData(data)

	assert.Equal(t, "json", run.OutputFormat())
}
