package suppression

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Scope defines the scope of an inline suppression.
type Scope string

const (
	// ScopeLine suppresses the finding on the next line only.
	ScopeLine Scope = "line"
	// ScopeBlock suppresses findings until the next blank line.
	ScopeBlock Scope = "block"
	// ScopeFile suppresses findings for the entire file.
	ScopeFile Scope = "file"
)

// InlineSuppression represents a suppression comment found in source code.
type InlineSuppression struct {
	File         string   // Relative file path
	Line         int      // Line number where the comment appears (1-based)
	RuleIDs      []string // Rule IDs being suppressed (e.g., G101, G102)
	Reason       string   // Optional reason provided in the comment
	Scope        Scope    // Scope of suppression (line, block, file)
	EffectiveEnd int      // Line number where suppression ends (for block scope)
}

// Parser parses inline suppression comments from Go source files.
type Parser struct {
	// Comment patterns
	linePattern  *regexp.Regexp
	blockPattern *regexp.Regexp
	filePattern  *regexp.Regexp
	rulePattern  *regexp.Regexp
	reasonPattern *regexp.Regexp
}

// NewParser creates a new inline suppression parser.
func NewParser() *Parser {
	return &Parser{
		// verdict:ignore G101 or verdict:ignore G101,G102
		linePattern:  regexp.MustCompile(`(?i)//\s*verdict:ignore\s+([A-Z0-9_,\-]+)`),
		// verdict:ignore-block G101
		blockPattern: regexp.MustCompile(`(?i)//\s*verdict:ignore-block\s+([A-Z0-9_,\-]+)`),
		// verdict:ignore-file G101
		filePattern:  regexp.MustCompile(`(?i)//\s*verdict:ignore-file\s+([A-Z0-9_,\-]+)`),
		// Match rule IDs
		rulePattern:  regexp.MustCompile(`[A-Z0-9_\-]+`),
		// Extract reason="..." or reason='...'
		reasonPattern: regexp.MustCompile(`reason\s*=\s*["']([^"']+)["']`),
	}
}

// ParseFile parses inline suppressions from a single file.
func (p *Parser) ParseFile(filePath string) ([]InlineSuppression, error) {
	// #nosec G304 -- filePath comes from findings locations, which are from scanning the target directory
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return p.parseReader(filePath, file)
}

// parseReader parses suppressions from a reader (for testing).
func (p *Parser) parseReader(filePath string, file *os.File) ([]InlineSuppression, error) {
	var suppressions []InlineSuppression

	scanner := bufio.NewScanner(file)
	lineNum := 0
	inBlock := false
	var blockSuppression *InlineSuppression

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Check for file-level suppression (must be near top of file)
		if lineNum <= 10 { // Only check first 10 lines for file-level
			if matches := p.filePattern.FindStringSubmatch(trimmed); matches != nil {
				suppression := p.createSuppression(filePath, lineNum, matches[1], trimmed, ScopeFile)
				suppressions = append(suppressions, suppression)
				continue
			}
		}

		// Check for block suppression start
		if matches := p.blockPattern.FindStringSubmatch(trimmed); matches != nil {
			if blockSuppression != nil {
				// Close previous block
				blockSuppression.EffectiveEnd = lineNum - 1
			}
			suppression := p.createSuppression(filePath, lineNum, matches[1], trimmed, ScopeBlock)
			blockSuppression = &suppression
			inBlock = true
			continue
		}

		// Check for line suppression
		if matches := p.linePattern.FindStringSubmatch(trimmed); matches != nil {
			suppression := p.createSuppression(filePath, lineNum, matches[1], trimmed, ScopeLine)
			suppressions = append(suppressions, suppression)
			continue
		}

		// End block on blank line
		if inBlock && trimmed == "" {
			if blockSuppression != nil {
				blockSuppression.EffectiveEnd = lineNum - 1
				suppressions = append(suppressions, *blockSuppression)
				blockSuppression = nil
			}
			inBlock = false
		}
	}

	// Close any open block at end of file
	if blockSuppression != nil {
		blockSuppression.EffectiveEnd = lineNum
		suppressions = append(suppressions, *blockSuppression)
	}

	if err := scanner.Err(); err != nil {
		return suppressions, err
	}

	return suppressions, nil
}

// createSuppression creates an InlineSuppression from parsed data.
func (p *Parser) createSuppression(filePath string, line int, ruleStr, fullLine string, scope Scope) InlineSuppression {
	// Parse rule IDs
	ruleIDs := p.rulePattern.FindAllString(ruleStr, -1)

	// Parse optional reason
	var reason string
	if matches := p.reasonPattern.FindStringSubmatch(fullLine); matches != nil {
		reason = matches[1]
	}

	return InlineSuppression{
		File:    filePath,
		Line:    line,
		RuleIDs: ruleIDs,
		Reason:  reason,
		Scope:   scope,
	}
}

// ParseDirectory recursively parses all Go files in a directory.
func (p *Parser) ParseDirectory(dir string) ([]InlineSuppression, error) {
	var allSuppressions []InlineSuppression

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip vendor, .git, testdata directories
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process Go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Parse the file
		suppressions, err := p.ParseFile(path)
		if err != nil {
			// Log error but continue processing other files
			return nil
		}

		// Make paths relative to the directory
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			relPath = path
		}

		for i := range suppressions {
			suppressions[i].File = relPath
		}

		allSuppressions = append(allSuppressions, suppressions...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return allSuppressions, nil
}

// SuppressionSet provides efficient lookup of suppressions.
type SuppressionSet struct {
	// byFile maps file path to suppressions in that file
	byFile map[string][]InlineSuppression
	// fileScopedRules maps file path to file-scoped rule IDs
	fileScopedRules map[string]map[string]bool
}

// NewSuppressionSet creates a SuppressionSet from a list of suppressions.
func NewSuppressionSet(suppressions []InlineSuppression) *SuppressionSet {
	set := &SuppressionSet{
		byFile:          make(map[string][]InlineSuppression),
		fileScopedRules: make(map[string]map[string]bool),
	}

	for _, supp := range suppressions {
		// Normalize path
		file := filepath.Clean(supp.File)

		// Add to file index
		set.byFile[file] = append(set.byFile[file], supp)

		// Track file-scoped rules
		if supp.Scope == ScopeFile {
			if set.fileScopedRules[file] == nil {
				set.fileScopedRules[file] = make(map[string]bool)
			}
			for _, ruleID := range supp.RuleIDs {
				set.fileScopedRules[file][ruleID] = true
			}
		}
	}

	return set
}

// IsSuppressed checks if a finding at the given location and rule is suppressed.
func (s *SuppressionSet) IsSuppressed(file string, line int, ruleID string) bool {
	file = filepath.Clean(file)

	// Check file-scoped suppressions first
	if rules, ok := s.fileScopedRules[file]; ok {
		if rules[ruleID] {
			return true
		}
	}

	// Check line and block suppressions
	suppressions, ok := s.byFile[file]
	if !ok {
		return false
	}

	for _, supp := range suppressions {
		// Skip file-scoped (already checked)
		if supp.Scope == ScopeFile {
			continue
		}

		// Check if rule matches
		if !containsRule(supp.RuleIDs, ruleID) {
			continue
		}

		switch supp.Scope {
		case ScopeLine:
			// Line suppression affects the next line
			if line == supp.Line+1 {
				return true
			}
		case ScopeBlock:
			// Block suppression affects lines from comment to effective end
			if line > supp.Line && line <= supp.EffectiveEnd {
				return true
			}
		}
	}

	return false
}

// GetSuppression returns the suppression that applies to a finding, if any.
func (s *SuppressionSet) GetSuppression(file string, line int, ruleID string) *InlineSuppression {
	file = filepath.Clean(file)

	suppressions, ok := s.byFile[file]
	if !ok {
		return nil
	}

	for _, supp := range suppressions {
		if !containsRule(supp.RuleIDs, ruleID) {
			continue
		}

		switch supp.Scope {
		case ScopeFile:
			return &supp
		case ScopeLine:
			if line == supp.Line+1 {
				return &supp
			}
		case ScopeBlock:
			if line > supp.Line && line <= supp.EffectiveEnd {
				return &supp
			}
		}
	}

	return nil
}

// Files returns all files that have suppressions.
func (s *SuppressionSet) Files() []string {
	files := make([]string, 0, len(s.byFile))
	for file := range s.byFile {
		files = append(files, file)
	}
	return files
}

// Count returns the total number of suppressions.
func (s *SuppressionSet) Count() int {
	count := 0
	for _, suppressions := range s.byFile {
		count += len(suppressions)
	}
	return count
}

// containsRule checks if a slice of rule IDs contains a specific rule.
func containsRule(ruleIDs []string, ruleID string) bool {
	for _, id := range ruleIDs {
		if strings.EqualFold(id, ruleID) {
			return true
		}
	}
	return false
}
