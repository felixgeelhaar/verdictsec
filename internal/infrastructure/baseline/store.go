package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	domainBaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/pkg/pathutil"
)

// Store handles reading and writing baseline files.
type Store struct {
	defaultPath string
}

// NewStore creates a new baseline store with the default path.
func NewStore() *Store {
	return &Store{
		defaultPath: ".verdict/baseline.json",
	}
}

// NewStoreWithPath creates a store with a custom default path.
func NewStoreWithPath(path string) *Store {
	return &Store{
		defaultPath: path,
	}
}

// BaselineFile represents the JSON structure of a baseline file.
type BaselineFile struct {
	Version      string           `json:"version"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	Description  string           `json:"description,omitempty"`
	Scope        BaselineScope    `json:"scope"`
	Fingerprints []FingerprintEntry `json:"fingerprints"`
}

// BaselineScope defines what the baseline covers.
type BaselineScope struct {
	Project  string   `json:"project,omitempty"`
	Branch   string   `json:"branch,omitempty"`
	Engines  []string `json:"engines,omitempty"`
}

// FingerprintEntry represents a single baselined finding.
type FingerprintEntry struct {
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"rule_id"`
	EngineID    string    `json:"engine_id"`
	File        string    `json:"file"`
	AddedAt     time.Time `json:"added_at"`
	Reason      string    `json:"reason,omitempty"`
	AddedBy     string    `json:"added_by,omitempty"`
}

// Load loads a baseline from the default path.
func (s *Store) Load() (*domainBaseline.Baseline, error) {
	return s.LoadFromPath(s.defaultPath)
}

// LoadFromPath loads a baseline from a specific path.
func (s *Store) LoadFromPath(path string) (*domainBaseline.Baseline, error) {
	// Validate path to prevent path traversal attacks
	cleanPath, err := pathutil.ValidatePath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid baseline path: %w", err)
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty baseline if file doesn't exist
			return domainBaseline.NewBaseline(""), nil
		}
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	return s.LoadFromBytes(data)
}

// LoadFromBytes loads a baseline from JSON bytes.
func (s *Store) LoadFromBytes(data []byte) (*domainBaseline.Baseline, error) {
	if len(data) == 0 {
		return domainBaseline.NewBaseline(""), nil
	}

	var file BaselineFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	// Convert to domain baseline using scope from file
	target := file.Scope.Project
	baseline := domainBaseline.NewBaseline(target)

	// Add entries directly using stored fingerprints (don't recalculate)
	for _, entry := range file.Fingerprints {
		baseline.AddEntry(
			entry.Fingerprint,
			finding.FingerprintVersion, // Use current fingerprint version
			entry.RuleID,
			entry.EngineID,
			entry.Reason,
		)
	}

	return baseline, nil
}

// Save saves a baseline to the default path.
func (s *Store) Save(baseline *domainBaseline.Baseline) error {
	return s.SaveToPath(baseline, s.defaultPath)
}

// SaveToPath saves a baseline to a specific path.
func (s *Store) SaveToPath(baseline *domainBaseline.Baseline, path string) error {
	file := s.toBaselineFile(baseline)

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create baseline directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// SaveWithMetadata saves a baseline with additional metadata.
func (s *Store) SaveWithMetadata(baseline *domainBaseline.Baseline, metadata BaselineMetadata) error {
	return s.SaveToPathWithMetadata(baseline, s.defaultPath, metadata)
}

// SaveToPathWithMetadata saves a baseline with metadata to a specific path.
func (s *Store) SaveToPathWithMetadata(baseline *domainBaseline.Baseline, path string, metadata BaselineMetadata) error {
	file := s.toBaselineFileWithMetadata(baseline, metadata)

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create baseline directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// BaselineMetadata provides additional context for a baseline.
type BaselineMetadata struct {
	Description string
	Project     string
	Branch      string
	Engines     []string
	AddedBy     string
}

// toBaselineFile converts a domain baseline to file format.
func (s *Store) toBaselineFile(baseline *domainBaseline.Baseline) *BaselineFile {
	now := time.Now().UTC()
	file := &BaselineFile{
		Version:      "1",
		CreatedAt:    now,
		UpdatedAt:    now,
		Fingerprints: make([]FingerprintEntry, 0),
	}

	for _, entry := range baseline.Entries {
		file.Fingerprints = append(file.Fingerprints, FingerprintEntry{
			Fingerprint: entry.Fingerprint,
			RuleID:      entry.RuleID,
			EngineID:    entry.EngineID,
			AddedAt:     entry.FirstSeen,
			Reason:      entry.Reason,
			AddedBy:     entry.AddedBy,
		})
	}

	return file
}

// toBaselineFileWithMetadata converts a domain baseline to file format with metadata.
func (s *Store) toBaselineFileWithMetadata(baseline *domainBaseline.Baseline, metadata BaselineMetadata) *BaselineFile {
	now := time.Now().UTC()
	file := &BaselineFile{
		Version:     "1",
		CreatedAt:   now,
		UpdatedAt:   now,
		Description: metadata.Description,
		Scope: BaselineScope{
			Project: metadata.Project,
			Branch:  metadata.Branch,
			Engines: metadata.Engines,
		},
		Fingerprints: make([]FingerprintEntry, 0),
	}

	for _, entry := range baseline.Entries {
		addedBy := entry.AddedBy
		if addedBy == "" && metadata.AddedBy != "" {
			addedBy = metadata.AddedBy
		}
		file.Fingerprints = append(file.Fingerprints, FingerprintEntry{
			Fingerprint: entry.Fingerprint,
			RuleID:      entry.RuleID,
			EngineID:    entry.EngineID,
			AddedAt:     entry.FirstSeen,
			Reason:      entry.Reason,
			AddedBy:     addedBy,
		})
	}

	return file
}

// Exists checks if a baseline file exists at the default path.
func (s *Store) Exists() bool {
	return s.ExistsAt(s.defaultPath)
}

// DefaultPath returns the default baseline file path.
func (s *Store) DefaultPath() string {
	return s.defaultPath
}

// LoadFrom loads a baseline from a specific path.
// This is an alias for LoadFromPath to implement ports.BaselineStore.
func (s *Store) LoadFrom(path string) (*domainBaseline.Baseline, error) {
	return s.LoadFromPath(path)
}

// SaveTo saves a baseline to a specific path.
// This is an alias for SaveToPath to implement ports.BaselineStore.
func (s *Store) SaveTo(baseline *domainBaseline.Baseline, path string) error {
	return s.SaveToPath(baseline, path)
}

// ExistsAt checks if a baseline file exists at a specific path.
func (s *Store) ExistsAt(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Delete removes the baseline file at the default path.
func (s *Store) Delete() error {
	return s.DeleteAt(s.defaultPath)
}

// DeleteAt removes the baseline file at a specific path.
func (s *Store) DeleteAt(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to delete baseline file: %w", err)
	}
	return nil
}

// CreateFromFindings creates a baseline from a slice of findings with a reason.
func CreateFromFindings(findings []*finding.Finding, reason string) (*domainBaseline.Baseline, error) {
	if reason == "" {
		return nil, fmt.Errorf("reason is required for baselining")
	}
	baseline := domainBaseline.NewBaseline("")
	if err := baseline.AddAll(findings, reason); err != nil {
		return nil, err
	}
	return baseline, nil
}

// UpdateFromFindings updates a baseline by adding new findings with a reason.
func UpdateFromFindings(baseline *domainBaseline.Baseline, findings []*finding.Finding, reason string) (*domainBaseline.Baseline, error) {
	if reason == "" {
		return nil, fmt.Errorf("reason is required for baselining")
	}
	if err := baseline.AddAll(findings, reason); err != nil {
		return nil, err
	}
	return baseline, nil
}

// MergeBaselines merges multiple baselines into one.
func MergeBaselines(baselines ...*domainBaseline.Baseline) *domainBaseline.Baseline {
	result := domainBaseline.NewBaseline("")
	for _, b := range baselines {
		result.Merge(b)
	}
	return result
}
