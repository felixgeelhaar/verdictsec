package prompt

import (
	"fmt"
	"strings"

	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// PosturePrompt generates a prompt for summarizing security posture.
func PosturePrompt(a *assessment.Assessment) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert assistant. Analyze the following security scan results and provide an executive summary of the security posture.\n\n")

	sb.WriteString("## Scan Summary\n\n")
	sb.WriteString(fmt.Sprintf("**Scan ID:** %s\n", a.ID()))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", a.Target()))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n", a.StartedAt().Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Decision:** %s\n", a.Decision()))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n", len(a.Findings())))

	// Severity breakdown
	severityCounts := countBySeverity(a.Findings())
	sb.WriteString("\n### Severity Breakdown\n\n")
	sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", severityCounts["critical"]))
	sb.WriteString(fmt.Sprintf("- **High:** %d\n", severityCounts["high"]))
	sb.WriteString(fmt.Sprintf("- **Medium:** %d\n", severityCounts["medium"]))
	sb.WriteString(fmt.Sprintf("- **Low:** %d\n", severityCounts["low"]))
	sb.WriteString(fmt.Sprintf("- **Info:** %d\n", severityCounts["info"]))

	// Type breakdown
	typeCounts := countByType(a.Findings())
	sb.WriteString("\n### Category Breakdown\n\n")
	for category, count := range typeCounts {
		sb.WriteString(fmt.Sprintf("- **%s:** %d\n", category, count))
	}

	// Sample of critical/high findings
	criticalFindings := filterBySeverity(a.Findings(), "critical", "high")
	if len(criticalFindings) > 0 {
		sb.WriteString("\n### Critical/High Severity Findings\n\n")
		maxSamples := 5
		if len(criticalFindings) < maxSamples {
			maxSamples = len(criticalFindings)
		}
		for i := 0; i < maxSamples; i++ {
			f := criticalFindings[i]
			sb.WriteString(fmt.Sprintf("- [%s] %s at %s\n", f.NormalizedSeverity(), f.Title(), f.Location().String()))
		}
		if len(criticalFindings) > maxSamples {
			sb.WriteString(fmt.Sprintf("- ... and %d more\n", len(criticalFindings)-maxSamples))
		}
	}

	sb.WriteString("\n## Instructions\n\n")
	sb.WriteString("Provide a comprehensive security posture assessment including:\n")
	sb.WriteString("1. An overall rating (excellent/good/fair/poor/critical)\n")
	sb.WriteString("2. A numeric score (0-100)\n")
	sb.WriteString("3. An executive summary (2-3 sentences)\n")
	sb.WriteString("4. Key security highlights (positive observations)\n")
	sb.WriteString("5. Main concerns requiring attention\n")
	sb.WriteString("6. Top recommendations for improvement\n")
	sb.WriteString("7. Category-wise assessment with improvement suggestions\n\n")

	sb.WriteString("Format your response as JSON:\n")
	sb.WriteString("```json\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"rating\": \"fair\",\n")
	sb.WriteString("  \"score\": 65,\n")
	sb.WriteString("  \"summary\": \"Executive summary here\",\n")
	sb.WriteString("  \"highlights\": [\"No hardcoded credentials\", \"Dependencies up to date\"],\n")
	sb.WriteString("  \"concerns\": [\"SQL injection vulnerability\", \"Missing input validation\"],\n")
	sb.WriteString("  \"recommendations\": [\"Implement parameterized queries\", \"Add input sanitization\"],\n")
	sb.WriteString("  \"categories\": [\n")
	sb.WriteString("    {\n")
	sb.WriteString("      \"category\": \"SAST\",\n")
	sb.WriteString("      \"count\": 5,\n")
	sb.WriteString("      \"critical\": 1,\n")
	sb.WriteString("      \"high\": 2,\n")
	sb.WriteString("      \"medium\": 2,\n")
	sb.WriteString("      \"low\": 0,\n")
	sb.WriteString("      \"top_issues\": \"SQL injection and XSS vulnerabilities\",\n")
	sb.WriteString("      \"improvement\": \"Focus on input validation\"\n")
	sb.WriteString("    }\n")
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")
	sb.WriteString("```\n")

	return sb.String()
}

func countBySeverity(findings []*finding.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		sev := strings.ToLower(f.NormalizedSeverity().String())
		counts[sev]++
	}
	return counts
}

func countByType(findings []*finding.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		typeName := f.Type().String()
		counts[typeName]++
	}
	return counts
}

func filterBySeverity(findings []*finding.Finding, severities ...string) []*finding.Finding {
	sevSet := make(map[string]bool)
	for _, s := range severities {
		sevSet[strings.ToLower(s)] = true
	}

	var result []*finding.Finding
	for _, f := range findings {
		sev := strings.ToLower(f.NormalizedSeverity().String())
		if sevSet[sev] {
			result = append(result, f)
		}
	}
	return result
}
