package prompt

import (
	"fmt"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// ExplainPrompt generates a prompt for explaining a security finding.
func ExplainPrompt(f *finding.Finding) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert assistant. Explain the following security finding to help a developer understand and address it.\n\n")

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

	sb.WriteString("\n## Instructions\n\n")
	sb.WriteString("Provide:\n")
	sb.WriteString("1. A brief summary (2-3 sentences) explaining what this finding means\n")
	sb.WriteString("2. Detailed explanation of why this is a security concern\n")
	sb.WriteString("3. The potential risk and impact if exploited\n")
	sb.WriteString("4. Any relevant security references (OWASP, CWE documentation)\n\n")

	sb.WriteString("Format your response as JSON with these fields:\n")
	sb.WriteString("```json\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"summary\": \"Brief summary\",\n")
	sb.WriteString("  \"details\": \"Detailed explanation\",\n")
	sb.WriteString("  \"risk_context\": \"Risk and impact information\",\n")
	sb.WriteString("  \"references\": [\"url1\", \"url2\"]\n")
	sb.WriteString("}\n")
	sb.WriteString("```\n")

	return sb.String()
}

func formatLocation(loc finding.Location) string {
	if loc.Line() > 0 {
		return fmt.Sprintf("%s:%d", loc.File(), loc.Line())
	}
	return loc.File()
}
