package prompt

import (
	"fmt"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// RemediatePrompt generates a prompt for remediation suggestions.
func RemediatePrompt(f *finding.Finding, opts ports.RemediationOptions) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert assistant. Provide remediation guidance for the following security finding.\n\n")

	sb.WriteString("## Finding Details\n\n")
	sb.WriteString(fmt.Sprintf("**Type:** %s\n", f.Type()))
	sb.WriteString(fmt.Sprintf("**Title:** %s\n", f.Title()))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", f.NormalizedSeverity()))
	sb.WriteString(fmt.Sprintf("**Rule ID:** %s\n", f.RuleID()))

	if f.Description() != "" {
		sb.WriteString(fmt.Sprintf("**Description:** %s\n", f.Description()))
	}

	sb.WriteString(fmt.Sprintf("**Location:** %s\n", formatLocation(f.Location())))

	if f.HasCWE() {
		sb.WriteString(fmt.Sprintf("**CWE:** %s\n", f.CWEID()))
	}
	if f.HasCVE() {
		sb.WriteString(fmt.Sprintf("**CVE:** %s\n", f.CVEID()))
	}
	if f.HasFix() {
		sb.WriteString(fmt.Sprintf("**Fix Version:** %s\n", f.FixVersion()))
	}

	if opts.Context != "" {
		sb.WriteString(fmt.Sprintf("\n**Additional Context:** %s\n", opts.Context))
	}

	sb.WriteString("\n## Instructions\n\n")
	sb.WriteString("Provide remediation guidance including:\n")
	sb.WriteString("1. Priority level (critical/high/medium/low)\n")
	sb.WriteString("2. Brief summary of the recommended fix\n")
	sb.WriteString("3. Step-by-step remediation instructions\n")
	sb.WriteString("4. Estimated effort to implement\n")
	sb.WriteString("5. Expected security impact of the fix\n")

	if opts.IncludeCode {
		maxSuggestions := opts.MaxSuggestions
		if maxSuggestions == 0 {
			maxSuggestions = 3
		}
		sb.WriteString(fmt.Sprintf("6. Up to %d code suggestions showing the fix\n", maxSuggestions))
	}

	sb.WriteString("\nFormat your response as JSON with these fields:\n")
	sb.WriteString("```json\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"priority\": \"high\",\n")
	sb.WriteString("  \"summary\": \"Brief fix summary\",\n")
	sb.WriteString("  \"steps\": [\"Step 1\", \"Step 2\"],\n")
	sb.WriteString("  \"effort\": \"Low - 15 minutes\",\n")
	sb.WriteString("  \"impact\": \"Eliminates SQL injection risk\",\n")

	if opts.IncludeCode {
		sb.WriteString("  \"code_suggestions\": [\n")
		sb.WriteString("    {\n")
		sb.WriteString("      \"description\": \"Use parameterized query\",\n")
		sb.WriteString("      \"file_path\": \"path/to/file.go\",\n")
		sb.WriteString("      \"line_start\": 10,\n")
		sb.WriteString("      \"line_end\": 12,\n")
		sb.WriteString("      \"original\": \"vulnerable code\",\n")
		sb.WriteString("      \"replacement\": \"fixed code\",\n")
		sb.WriteString("      \"language\": \"go\"\n")
		sb.WriteString("    }\n")
		sb.WriteString("  ],\n")
	}

	sb.WriteString("  \"references\": [\"url1\", \"url2\"]\n")
	sb.WriteString("}\n")
	sb.WriteString("```\n")

	return sb.String()
}
