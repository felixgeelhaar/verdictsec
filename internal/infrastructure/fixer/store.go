// Package fixer provides functionality for applying AI-generated code fixes.
package fixer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

const (
	// DefaultStorePath is the default location for scan result storage.
	DefaultStorePath = ".verdict/last-scan.json"
	// BackupDir is the directory for file backups before applying fixes.
	BackupDir = ".verdict/backups"
)

// ScanResult represents a stored scan result with findings and remediations.
type ScanResult struct {
	ScanTime     time.Time                        `json:"scan_time"`
	Target       string                           `json:"target"`
	Findings     []*finding.Finding               `json:"findings"`
	Remediations map[string]*advisory.Remediation `json:"remediations,omitempty"`
}

// Store manages persistence of scan results for fix lookups.
type Store struct {
	path string
}

// NewStore creates a new store with the default path.
func NewStore() *Store {
	return &Store{
		path: DefaultStorePath,
	}
}

// NewStoreWithPath creates a store with a custom path.
func NewStoreWithPath(path string) *Store {
	return &Store{
		path: path,
	}
}

// Save persists a scan result to disk.
func (s *Store) Save(result *ScanResult) error {
	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write scan result: %w", err)
	}

	return nil
}

// SaveFromAssessment creates and saves a ScanResult from an Assessment.
func (s *Store) SaveFromAssessment(a *assessment.Assessment) error {
	result := &ScanResult{
		ScanTime:     time.Now().UTC(),
		Target:       a.Target(),
		Findings:     a.Findings(),
		Remediations: make(map[string]*advisory.Remediation),
	}
	return s.Save(result)
}

// Load reads a scan result from disk.
func (s *Store) Load() (*ScanResult, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no scan results found. Run 'verdict scan' first")
		}
		return nil, fmt.Errorf("failed to read scan result: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}

	return &result, nil
}

// GetFinding retrieves a finding by its ID.
func (s *Store) GetFinding(findingID string) (*finding.Finding, error) {
	result, err := s.Load()
	if err != nil {
		return nil, err
	}

	for _, f := range result.Findings {
		if f.ID() == findingID {
			return f, nil
		}
	}

	return nil, fmt.Errorf("finding %q not found", findingID)
}

// GetRemediation retrieves a stored remediation for a finding.
func (s *Store) GetRemediation(findingID string) (*advisory.Remediation, error) {
	result, err := s.Load()
	if err != nil {
		return nil, err
	}

	if rem, ok := result.Remediations[findingID]; ok {
		return rem, nil
	}

	return nil, nil // No remediation cached
}

// SaveRemediation stores a remediation for a finding.
func (s *Store) SaveRemediation(findingID string, rem *advisory.Remediation) error {
	result, err := s.Load()
	if err != nil {
		return err
	}

	if result.Remediations == nil {
		result.Remediations = make(map[string]*advisory.Remediation)
	}

	result.Remediations[findingID] = rem
	return s.Save(result)
}

// ListFindings returns all findings with optional remediation status.
func (s *Store) ListFindings() ([]*finding.Finding, map[string]bool, error) {
	result, err := s.Load()
	if err != nil {
		return nil, nil, err
	}

	hasRemediation := make(map[string]bool)
	for _, f := range result.Findings {
		if _, ok := result.Remediations[f.ID()]; ok {
			hasRemediation[f.ID()] = true
		}
	}

	return result.Findings, hasRemediation, nil
}

// Exists checks if a scan result file exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Path returns the store path.
func (s *Store) Path() string {
	return s.path
}

// Clear removes the scan result file.
func (s *Store) Clear() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove scan result: %w", err)
	}
	return nil
}
