package policy

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestDefaultThreshold(t *testing.T) {
	threshold := DefaultThreshold()

	assert.Equal(t, finding.SeverityHigh, threshold.FailOn)
	assert.Equal(t, finding.SeverityMedium, threshold.WarnOn)
}

func TestThreshold_ShouldFail(t *testing.T) {
	threshold := Threshold{
		FailOn: finding.SeverityHigh,
		WarnOn: finding.SeverityMedium,
	}

	assert.True(t, threshold.ShouldFail(finding.SeverityCritical))
	assert.True(t, threshold.ShouldFail(finding.SeverityHigh))
	assert.False(t, threshold.ShouldFail(finding.SeverityMedium))
	assert.False(t, threshold.ShouldFail(finding.SeverityLow))
}

func TestThreshold_ShouldWarn(t *testing.T) {
	threshold := Threshold{
		FailOn: finding.SeverityHigh,
		WarnOn: finding.SeverityMedium,
	}

	assert.False(t, threshold.ShouldWarn(finding.SeverityCritical)) // Should fail, not warn
	assert.False(t, threshold.ShouldWarn(finding.SeverityHigh))     // Should fail, not warn
	assert.True(t, threshold.ShouldWarn(finding.SeverityMedium))
	assert.False(t, threshold.ShouldWarn(finding.SeverityLow))
}

func TestThreshold_Validate(t *testing.T) {
	// Valid threshold
	threshold := DefaultThreshold()
	assert.NoError(t, threshold.Validate())

	// Invalid fail_on
	threshold = Threshold{
		FailOn: finding.Severity(99),
		WarnOn: finding.SeverityMedium,
	}
	assert.Error(t, threshold.Validate())

	// Invalid warn_on
	threshold = Threshold{
		FailOn: finding.SeverityHigh,
		WarnOn: finding.Severity(99),
	}
	assert.Error(t, threshold.Validate())

	// warn_on higher than fail_on
	threshold = Threshold{
		FailOn: finding.SeverityMedium,
		WarnOn: finding.SeverityHigh,
	}
	assert.Error(t, threshold.Validate())
}
