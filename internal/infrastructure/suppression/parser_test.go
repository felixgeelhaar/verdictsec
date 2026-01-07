package suppression

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParser_ParseFile(t *testing.T) {
	// Create temp file with suppressions
	content := `package main

// verdict:ignore-file G501

func main() {
	// verdict:ignore G101
	password := "secret123"

	// verdict:ignore G102,G103 reason="false positive"
	data := getUserInput()

	// verdict:ignore-block G201
	query := "SELECT * FROM users"
	rows := db.Query(query)
	_ = rows

	// This line is not suppressed
	anotherQuery := "SELECT * FROM orders"
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := NewParser()
	suppressions, err := parser.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Check that we found the expected suppressions
	if len(suppressions) < 3 {
		t.Errorf("Expected at least 3 suppressions, got %d", len(suppressions))
	}

	// Check file-level suppression
	var fileSupp *InlineSuppression
	for i := range suppressions {
		if suppressions[i].Scope == ScopeFile {
			fileSupp = &suppressions[i]
			break
		}
	}
	if fileSupp == nil {
		t.Error("Expected to find file-level suppression")
	} else {
		if len(fileSupp.RuleIDs) != 1 || fileSupp.RuleIDs[0] != "G501" {
			t.Errorf("Expected file suppression for G501, got %v", fileSupp.RuleIDs)
		}
	}

	// Check line suppression with reason
	var lineSupp *InlineSuppression
	for i := range suppressions {
		if suppressions[i].Scope == ScopeLine && len(suppressions[i].RuleIDs) == 2 {
			lineSupp = &suppressions[i]
			break
		}
	}
	if lineSupp == nil {
		t.Error("Expected to find multi-rule line suppression")
	} else {
		if lineSupp.Reason != "false positive" {
			t.Errorf("Expected reason 'false positive', got %q", lineSupp.Reason)
		}
	}

	// Check block suppression
	var blockSupp *InlineSuppression
	for i := range suppressions {
		if suppressions[i].Scope == ScopeBlock {
			blockSupp = &suppressions[i]
			break
		}
	}
	if blockSupp == nil {
		t.Error("Expected to find block suppression")
	} else {
		if len(blockSupp.RuleIDs) != 1 || blockSupp.RuleIDs[0] != "G201" {
			t.Errorf("Expected block suppression for G201, got %v", blockSupp.RuleIDs)
		}
	}
}

func TestParser_LineScope(t *testing.T) {
	content := `package main

func main() {
	// verdict:ignore G101
	password := "secret123"
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := NewParser()
	suppressions, err := parser.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(suppressions) != 1 {
		t.Fatalf("Expected 1 suppression, got %d", len(suppressions))
	}

	supp := suppressions[0]
	if supp.Scope != ScopeLine {
		t.Errorf("Expected ScopeLine, got %v", supp.Scope)
	}
	if supp.Line != 4 {
		t.Errorf("Expected line 4, got %d", supp.Line)
	}
	if len(supp.RuleIDs) != 1 || supp.RuleIDs[0] != "G101" {
		t.Errorf("Expected rule G101, got %v", supp.RuleIDs)
	}
}

func TestParser_MultipleRules(t *testing.T) {
	content := `package main

func main() {
	// verdict:ignore G101,G102,G103
	password := "secret123"
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := NewParser()
	suppressions, err := parser.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(suppressions) != 1 {
		t.Fatalf("Expected 1 suppression, got %d", len(suppressions))
	}

	supp := suppressions[0]
	if len(supp.RuleIDs) != 3 {
		t.Errorf("Expected 3 rules, got %d: %v", len(supp.RuleIDs), supp.RuleIDs)
	}
}

func TestParser_ReasonExtraction(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name: "double quotes",
			content: `package main
// verdict:ignore G101 reason="false positive"
var x = 1
`,
			expected: "false positive",
		},
		{
			name: "single quotes",
			content: `package main
// verdict:ignore G101 reason='known issue'
var x = 1
`,
			expected: "known issue",
		},
		{
			name: "no reason",
			content: `package main
// verdict:ignore G101
var x = 1
`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.go")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			parser := NewParser()
			suppressions, err := parser.ParseFile(tmpFile)
			if err != nil {
				t.Fatalf("ParseFile failed: %v", err)
			}

			if len(suppressions) != 1 {
				t.Fatalf("Expected 1 suppression, got %d", len(suppressions))
			}

			if suppressions[0].Reason != tt.expected {
				t.Errorf("Expected reason %q, got %q", tt.expected, suppressions[0].Reason)
			}
		})
	}
}

func TestParser_BlockScope(t *testing.T) {
	content := `package main

func main() {
	// verdict:ignore-block G201
	query1 := "SELECT * FROM users"
	query2 := "SELECT * FROM orders"
	query3 := "SELECT * FROM products"

	// This is after the blank line
	notSuppressed := "SELECT * FROM logs"
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := NewParser()
	suppressions, err := parser.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(suppressions) != 1 {
		t.Fatalf("Expected 1 suppression, got %d", len(suppressions))
	}

	supp := suppressions[0]
	if supp.Scope != ScopeBlock {
		t.Errorf("Expected ScopeBlock, got %v", supp.Scope)
	}
	if supp.Line != 4 {
		t.Errorf("Expected line 4, got %d", supp.Line)
	}
	if supp.EffectiveEnd != 7 {
		t.Errorf("Expected EffectiveEnd 7, got %d", supp.EffectiveEnd)
	}
}

func TestSuppressionSet_IsSuppressed(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "main.go", Line: 10, RuleIDs: []string{"G201"}, Scope: ScopeBlock, EffectiveEnd: 15},
		{File: "util.go", Line: 1, RuleIDs: []string{"G301"}, Scope: ScopeFile},
	}

	set := NewSuppressionSet(suppressions)

	tests := []struct {
		name     string
		file     string
		line     int
		ruleID   string
		expected bool
	}{
		{"line suppression - suppressed", "main.go", 6, "G101", true},
		{"line suppression - wrong line", "main.go", 7, "G101", false},
		{"line suppression - wrong rule", "main.go", 6, "G102", false},
		{"block suppression - in block", "main.go", 12, "G201", true},
		{"block suppression - before block", "main.go", 10, "G201", false},
		{"block suppression - after block", "main.go", 16, "G201", false},
		{"file suppression - any line", "util.go", 50, "G301", true},
		{"file suppression - wrong rule", "util.go", 50, "G302", false},
		{"no suppressions for file", "other.go", 1, "G101", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := set.IsSuppressed(tt.file, tt.line, tt.ruleID)
			if result != tt.expected {
				t.Errorf("IsSuppressed(%q, %d, %q) = %v, want %v",
					tt.file, tt.line, tt.ruleID, result, tt.expected)
			}
		})
	}
}

func TestSuppressionSet_GetSuppression(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 5, RuleIDs: []string{"G101"}, Scope: ScopeLine, Reason: "known issue"},
		{File: "main.go", Line: 10, RuleIDs: []string{"G201"}, Scope: ScopeFile},
	}

	set := NewSuppressionSet(suppressions)

	// Should find line suppression
	supp := set.GetSuppression("main.go", 6, "G101")
	if supp == nil {
		t.Error("Expected to find suppression")
	} else if supp.Reason != "known issue" {
		t.Errorf("Expected reason 'known issue', got %q", supp.Reason)
	}

	// Should find file suppression
	supp = set.GetSuppression("main.go", 100, "G201")
	if supp == nil {
		t.Error("Expected to find file suppression")
	}

	// Should not find suppression
	supp = set.GetSuppression("main.go", 100, "G999")
	if supp != nil {
		t.Error("Expected nil for unsuppressed rule")
	}
}

func TestParser_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name    string
		comment string
	}{
		{"lowercase", "// verdict:ignore G101"},
		{"uppercase", "// VERDICT:IGNORE G101"},
		{"mixed case", "// Verdict:Ignore G101"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := "package main\n" + tt.comment + "\nvar x = 1\n"
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.go")
			if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}

			parser := NewParser()
			suppressions, err := parser.ParseFile(tmpFile)
			if err != nil {
				t.Fatalf("ParseFile failed: %v", err)
			}

			if len(suppressions) != 1 {
				t.Errorf("Expected 1 suppression, got %d", len(suppressions))
			}
		})
	}
}

func TestParser_ParseDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple files
	files := map[string]string{
		"main.go": `package main
// verdict:ignore G101
var secret = "password"
`,
		"util/helper.go": `package util
// verdict:ignore G201
func helper() {}
`,
		"vendor/dep/dep.go": `package dep
// verdict:ignore G301
var x = 1
`,
	}

	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	parser := NewParser()
	suppressions, err := parser.ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	// Should find suppressions from main.go and util/helper.go but not vendor
	if len(suppressions) != 2 {
		t.Errorf("Expected 2 suppressions (excluding vendor), got %d", len(suppressions))
	}

	// Check that paths are relative
	for _, supp := range suppressions {
		if filepath.IsAbs(supp.File) {
			t.Errorf("Expected relative path, got absolute: %s", supp.File)
		}
	}
}

func TestSuppressionSet_Count(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "a.go", Line: 1, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "a.go", Line: 5, RuleIDs: []string{"G102"}, Scope: ScopeLine},
		{File: "b.go", Line: 1, RuleIDs: []string{"G201"}, Scope: ScopeFile},
	}

	set := NewSuppressionSet(suppressions)

	if count := set.Count(); count != 3 {
		t.Errorf("Expected count 3, got %d", count)
	}
}

func TestSuppressionSet_Files(t *testing.T) {
	suppressions := []InlineSuppression{
		{File: "main.go", Line: 1, RuleIDs: []string{"G101"}, Scope: ScopeLine},
		{File: "main.go", Line: 5, RuleIDs: []string{"G102"}, Scope: ScopeLine},
		{File: "util.go", Line: 1, RuleIDs: []string{"G201"}, Scope: ScopeFile},
	}

	set := NewSuppressionSet(suppressions)
	files := set.Files()

	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}
}

func TestContainsRule(t *testing.T) {
	tests := []struct {
		ruleIDs  []string
		ruleID   string
		expected bool
	}{
		{[]string{"G101", "G102"}, "G101", true},
		{[]string{"G101", "G102"}, "g101", true}, // case insensitive
		{[]string{"G101", "G102"}, "G103", false},
		{[]string{}, "G101", false},
	}

	for _, tt := range tests {
		result := containsRule(tt.ruleIDs, tt.ruleID)
		if result != tt.expected {
			t.Errorf("containsRule(%v, %q) = %v, want %v",
				tt.ruleIDs, tt.ruleID, result, tt.expected)
		}
	}
}
