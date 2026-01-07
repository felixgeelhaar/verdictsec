package trivy

import (
	"testing"
)

func TestParser_Parse_Vulnerabilities(t *testing.T) {
	input := `{
		"SchemaVersion": 2,
		"ArtifactName": "alpine:3.18",
		"ArtifactType": "container_image",
		"Results": [
			{
				"Target": "alpine:3.18 (alpine 3.18.0)",
				"Class": "os-pkgs",
				"Type": "alpine",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-1234",
						"PkgID": "openssl@1.1.1",
						"PkgName": "openssl",
						"InstalledVersion": "1.1.1",
						"FixedVersion": "1.1.2",
						"Status": "fixed",
						"Severity": "HIGH",
						"Title": "OpenSSL vulnerability",
						"Description": "A vulnerability in OpenSSL allows remote attackers...",
						"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
						"References": ["https://example.com"],
						"CweIDs": ["CWE-79"]
					}
				]
			}
		]
	}`

	parser := NewParser()
	findings, err := parser.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2023-1234" {
		t.Errorf("expected RuleID 'CVE-2023-1234', got %q", f.RuleID)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected Severity 'HIGH', got %q", f.Severity)
	}
	if f.Metadata["package"] != "openssl" {
		t.Errorf("expected package 'openssl', got %q", f.Metadata["package"])
	}
	if f.Metadata["fixed_version"] != "1.1.2" {
		t.Errorf("expected fixed_version '1.1.2', got %q", f.Metadata["fixed_version"])
	}
	if f.Metadata["cwe"] != "CWE-79" {
		t.Errorf("expected cwe 'CWE-79', got %q", f.Metadata["cwe"])
	}
}

func TestParser_Parse_Secrets(t *testing.T) {
	input := `{
		"SchemaVersion": 2,
		"ArtifactName": ".",
		"ArtifactType": "filesystem",
		"Results": [
			{
				"Target": "config/secrets.go",
				"Class": "secret",
				"Secrets": [
					{
						"RuleID": "aws-access-key-id",
						"Category": "AWS",
						"Severity": "CRITICAL",
						"Title": "AWS Access Key ID",
						"StartLine": 10,
						"EndLine": 10,
						"Match": "AKIA...",
						"Code": {
							"Lines": [
								{
									"Number": 10,
									"Content": "key := \"AKIAIOSFODNN7EXAMPLE\"",
									"IsCause": true
								}
							]
						}
					}
				]
			}
		]
	}`

	parser := NewParser()
	findings, err := parser.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "aws-access-key-id" {
		t.Errorf("expected RuleID 'aws-access-key-id', got %q", f.RuleID)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("expected Severity 'CRITICAL', got %q", f.Severity)
	}
	if f.StartLine != 10 {
		t.Errorf("expected StartLine 10, got %d", f.StartLine)
	}
	if f.Metadata["type"] != "secret" {
		t.Errorf("expected type 'secret', got %q", f.Metadata["type"])
	}
	if f.Snippet != "[REDACTED]" {
		t.Errorf("expected snippet '[REDACTED]', got %q", f.Snippet)
	}
}

func TestParser_Parse_EmptyInput(t *testing.T) {
	parser := NewParser()
	findings, err := parser.Parse([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings, got %v", findings)
	}
}

func TestParser_Parse_NoResults(t *testing.T) {
	input := `{
		"SchemaVersion": 2,
		"ArtifactName": ".",
		"ArtifactType": "filesystem",
		"Results": []
	}`

	parser := NewParser()
	findings, err := parser.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()
	_, err := parser.Parse([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
