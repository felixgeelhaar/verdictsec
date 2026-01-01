// Package exitcode defines exit codes for the verdict CLI.
package exitcode

import (
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
)

// Exit codes follow a standard convention:
// 0 = Success (PASS or WARN in local mode)
// 1 = Policy violation (FAIL)
// 2 = Tool/config error (ERROR)
const (
	// Success indicates no policy violations.
	Success = 0

	// PolicyViolation indicates a policy violation was detected.
	PolicyViolation = 1

	// Error indicates a tool or configuration error.
	Error = 2
)

// FromDecision converts an assessment decision to an exit code.
func FromDecision(d assessment.Decision, strictMode bool) int {
	switch d {
	case assessment.DecisionPass:
		return Success
	case assessment.DecisionWarn:
		if strictMode {
			return PolicyViolation
		}
		return Success
	case assessment.DecisionFail:
		return PolicyViolation
	case assessment.DecisionError:
		return Error
	default:
		return Error
	}
}

// Description returns a human-readable description of the exit code.
func Description(code int) string {
	switch code {
	case Success:
		return "No policy violations detected"
	case PolicyViolation:
		return "Policy violation detected"
	case Error:
		return "Tool or configuration error"
	default:
		return "Unknown exit code"
	}
}

// IsSuccess returns true if the exit code indicates success.
func IsSuccess(code int) bool {
	return code == Success
}

// IsViolation returns true if the exit code indicates a policy violation.
func IsViolation(code int) bool {
	return code == PolicyViolation
}

// IsError returns true if the exit code indicates an error.
func IsError(code int) bool {
	return code == Error
}
