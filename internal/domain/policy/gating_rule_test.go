package policy

import (
	"testing"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/stretchr/testify/assert"
)

func TestGatingRule_Validate(t *testing.T) {
	// Valid rule
	rule := GatingRule{
		Mode: ModeCI,
		Threshold: Threshold{
			FailOn: finding.SeverityHigh,
			WarnOn: finding.SeverityMedium,
		},
	}
	assert.NoError(t, rule.Validate())

	// Invalid mode
	rule = GatingRule{
		Mode: "invalid",
		Threshold: Threshold{
			FailOn: finding.SeverityHigh,
			WarnOn: finding.SeverityMedium,
		},
	}
	assert.Error(t, rule.Validate())

	// Invalid threshold
	rule = GatingRule{
		Mode: ModeLocal,
		Threshold: Threshold{
			FailOn: finding.SeverityMedium,
			WarnOn: finding.SeverityHigh, // Higher than fail_on
		},
	}
	assert.Error(t, rule.Validate())
}
