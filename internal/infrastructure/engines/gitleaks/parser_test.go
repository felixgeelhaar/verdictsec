package gitleaks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	parser := NewParser()
	assert.NotNil(t, parser)
}

func TestParser_Parse_EmptyData(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte{})

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_NullResponse(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte("null"))

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_EmptyArray(t *testing.T) {
	parser := NewParser()

	findings, err := parser.Parse([]byte("[]"))

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParser_Parse_ValidOutput(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"Description": "AWS Access Key ID",
			"StartLine": 10,
			"EndLine": 10,
			"StartColumn": 15,
			"EndColumn": 35,
			"Match": "AKIAIOSFODNN7EXAMPLE",
			"Secret": "AKIAIOSFODNN7EXAMPLE",
			"File": "config.go",
			"Commit": "abc123",
			"Entropy": 3.5,
			"Author": "dev@example.com",
			"RuleID": "aws-access-key-id",
			"Fingerprint": "config.go:aws-access-key-id:10"
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "aws-access-key-id", f.RuleID)
	assert.Equal(t, "AWS Access Key ID", f.Message)
	assert.Equal(t, "HIGH", f.Severity)
	assert.Equal(t, "config.go", f.File)
	assert.Equal(t, 10, f.StartLine)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", f.Metadata["secret"])
	assert.Equal(t, "abc123", f.Metadata["commit"])
}

func TestParser_Parse_MultipleFindings(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"Description": "AWS Access Key ID",
			"StartLine": 10,
			"File": "config.go",
			"Secret": "AKIAIOSFODNN7EXAMPLE",
			"RuleID": "aws-access-key-id"
		},
		{
			"Description": "GitHub Token",
			"StartLine": 20,
			"File": "auth.go",
			"Secret": "ghp_xxxxxxxxxxxx",
			"RuleID": "github-pat"
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	assert.Len(t, findings, 2)
	assert.Equal(t, "aws-access-key-id", findings[0].RuleID)
	assert.Equal(t, "github-pat", findings[1].RuleID)
}

func TestParser_Parse_NoDescription(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"StartLine": 10,
			"File": "config.go",
			"Secret": "secret123",
			"RuleID": "generic-secret"
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "generic-secret")
}

func TestParser_Parse_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.Parse([]byte(`{invalid json}`))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal gitleaks output")
}

func TestParser_GetSecretCount(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{"RuleID": "rule1", "Secret": "s1", "File": "a.go", "StartLine": 1},
		{"RuleID": "rule2", "Secret": "s2", "File": "b.go", "StartLine": 2}
	]`)

	count, err := parser.GetSecretCount(input)

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParser_Parse_WithEntropy(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"RuleID": "generic-secret",
			"Secret": "high_entropy_secret",
			"File": "test.go",
			"StartLine": 1,
			"Entropy": 4.5
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "4.50", findings[0].Metadata["entropy"])
}

func TestParser_GetSecretCount_EmptyData(t *testing.T) {
	parser := NewParser()

	count, err := parser.GetSecretCount([]byte{})

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestParser_GetSecretCount_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.GetSecretCount([]byte(`{invalid json}`))

	assert.Error(t, err)
}

func TestParser_Parse_WithMatch(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"RuleID": "generic-secret",
			"Description": "Secret found",
			"Secret": "mysecret",
			"Match": "password=mysecret",
			"File": "test.go",
			"StartLine": 1,
			"EndLine": 1,
			"StartColumn": 5,
			"EndColumn": 22
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "password=mysecret", findings[0].Metadata["match"])
	assert.Equal(t, 5, findings[0].StartColumn)
	assert.Equal(t, 22, findings[0].EndColumn)
}

func TestParser_Parse_WithAuthor(t *testing.T) {
	parser := NewParser()
	input := []byte(`[
		{
			"RuleID": "generic-secret",
			"Secret": "mysecret",
			"File": "test.go",
			"StartLine": 1,
			"Author": "developer@example.com"
		}
	]`)

	findings, err := parser.Parse(input)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "developer@example.com", findings[0].Metadata["author"])
}
