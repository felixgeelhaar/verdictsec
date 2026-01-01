package baseline

import "errors"

// Sentinel errors for baseline operations.
var (
	// ErrReasonRequired is returned when a baseline operation requires a reason
	// but none was provided.
	ErrReasonRequired = errors.New("reason is required for baselining")

	// ErrBaselineNotFound is returned when trying to load a baseline that
	// doesn't exist.
	ErrBaselineNotFound = errors.New("baseline not found")

	// ErrInvalidFingerprint is returned when an invalid fingerprint is provided.
	ErrInvalidFingerprint = errors.New("invalid fingerprint")

	// ErrEntryNotFound is returned when a baseline entry is not found.
	ErrEntryNotFound = errors.New("baseline entry not found")
)
