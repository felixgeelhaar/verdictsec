package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/advisory"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai/prompt"
)

const (
	defaultBaseURL = "https://api.anthropic.com/v1"
	defaultModel   = "claude-3-5-sonnet-20241022"
	apiVersion     = "2023-06-01"
)

// Adapter implements the ports.Advisor interface using Claude API.
type Adapter struct {
	apiKey   string
	baseURL  string
	model    string
	client   *http.Client
	features ports.AdvisorFeatures
}

// Option configures the Claude adapter.
type Option func(*Adapter)

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(a *Adapter) { a.apiKey = key }
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(a *Adapter) { a.baseURL = url }
}

// WithModel sets the model to use.
func WithModel(model string) Option {
	return func(a *Adapter) { a.model = model }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(a *Adapter) { a.client = client }
}

// WithFeatures sets the enabled features.
func WithFeatures(features ports.AdvisorFeatures) Option {
	return func(a *Adapter) { a.features = features }
}

// NewAdapter creates a new Claude adapter.
func NewAdapter(opts ...Option) *Adapter {
	a := &Adapter{
		apiKey:  os.Getenv("ANTHROPIC_API_KEY"),
		baseURL: defaultBaseURL,
		model:   defaultModel,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		features: ports.AdvisorFeatures{
			Explain:   true,
			Remediate: true,
			Summarize: true,
		},
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Provider returns "claude".
func (a *Adapter) Provider() string { return "claude" }

// Model returns the configured model ID.
func (a *Adapter) Model() string { return a.model }

// IsAvailable returns true if the adapter is configured with an API key.
func (a *Adapter) IsAvailable() bool { return a.apiKey != "" }

// Explain generates an explanation for a security finding.
func (a *Adapter) Explain(ctx context.Context, f *finding.Finding) (*advisory.Explanation, error) {
	if !a.features.Explain {
		return nil, ports.ErrFeatureDisabled{Feature: "explain"}
	}

	promptText := prompt.ExplainPrompt(f)
	response, err := a.sendMessage(ctx, promptText)
	if err != nil {
		return nil, fmt.Errorf("claude explain: %w", err)
	}

	var result struct {
		Summary     string   `json:"summary"`
		Details     string   `json:"details"`
		RiskContext string   `json:"risk_context"`
		References  []string `json:"references"`
	}

	if err := extractJSON(response, &result); err != nil {
		return nil, fmt.Errorf("claude explain: parse response: %w", err)
	}

	explanation := advisory.NewExplanation(
		f.ID(),
		result.Summary,
		"claude",
		a.model,
		advisory.WithDetails(result.Details),
		advisory.WithRiskContext(result.RiskContext),
		advisory.WithReferences(result.References),
	)

	return explanation, nil
}

// Remediate generates remediation suggestions for a finding.
func (a *Adapter) Remediate(ctx context.Context, f *finding.Finding, opts ports.RemediationOptions) (*advisory.Remediation, error) {
	if !a.features.Remediate {
		return nil, ports.ErrFeatureDisabled{Feature: "remediate"}
	}

	promptText := prompt.RemediatePrompt(f, opts)
	response, err := a.sendMessage(ctx, promptText)
	if err != nil {
		return nil, fmt.Errorf("claude remediate: %w", err)
	}

	var result struct {
		Priority        string                     `json:"priority"`
		Summary         string                     `json:"summary"`
		Steps           []string                   `json:"steps"`
		Effort          string                     `json:"effort"`
		Impact          string                     `json:"impact"`
		CodeSuggestions []advisory.CodeSuggestion `json:"code_suggestions"`
		References      []string                   `json:"references"`
	}

	if err := extractJSON(response, &result); err != nil {
		return nil, fmt.Errorf("claude remediate: parse response: %w", err)
	}

	priority := mapPriority(result.Priority)
	remediation := advisory.NewRemediation(
		f.ID(),
		priority,
		result.Summary,
		"claude",
		a.model,
		advisory.WithSteps(result.Steps),
		advisory.WithCodeSuggestions(result.CodeSuggestions),
		advisory.WithEffort(result.Effort),
		advisory.WithImpact(result.Impact),
		advisory.WithRemediationReferences(result.References),
	)

	return remediation, nil
}

// Summarize generates a posture summary for an assessment.
func (a *Adapter) Summarize(ctx context.Context, assess *assessment.Assessment) (*advisory.PostureSummary, error) {
	if !a.features.Summarize {
		return nil, ports.ErrFeatureDisabled{Feature: "summarize"}
	}

	promptText := prompt.PosturePrompt(assess)
	response, err := a.sendMessage(ctx, promptText)
	if err != nil {
		return nil, fmt.Errorf("claude summarize: %w", err)
	}

	var result struct {
		Rating          string                    `json:"rating"`
		Score           int                       `json:"score"`
		Summary         string                    `json:"summary"`
		Highlights      []string                  `json:"highlights"`
		Concerns        []string                  `json:"concerns"`
		Recommendations []string                  `json:"recommendations"`
		Categories      []advisory.CategorySummary `json:"categories"`
	}

	if err := extractJSON(response, &result); err != nil {
		return nil, fmt.Errorf("claude summarize: parse response: %w", err)
	}

	rating := mapRating(result.Rating)
	summary := advisory.NewPostureSummary(
		assess.ID(),
		rating,
		result.Score,
		result.Summary,
		"claude",
		a.model,
		advisory.WithHighlights(result.Highlights),
		advisory.WithConcerns(result.Concerns),
		advisory.WithPostureRecommendations(result.Recommendations),
		advisory.WithCategories(result.Categories),
	)

	return summary, nil
}

// sendMessage sends a message to Claude and returns the response text.
func (a *Adapter) sendMessage(ctx context.Context, content string) (string, error) {
	reqBody := map[string]any{
		"model":      a.model,
		"max_tokens": 4096,
		"messages": []map[string]string{
			{"role": "user", "content": content},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("claude API error: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}

	return apiResp.Content[0].Text, nil
}

// extractJSON parses a JSON code block from the response text.
func extractJSON(text string, v any) error {
	// Try to find JSON between ```json and ``` markers
	start := bytes.Index([]byte(text), []byte("```json"))
	if start == -1 {
		// Try without json marker
		start = bytes.Index([]byte(text), []byte("```"))
		if start == -1 {
			// Assume entire text is JSON
			return json.Unmarshal([]byte(text), v)
		}
	}

	// Skip the marker
	jsonStart := bytes.Index([]byte(text[start:]), []byte("\n"))
	if jsonStart == -1 {
		return fmt.Errorf("malformed JSON block")
	}
	text = text[start+jsonStart+1:]

	// Find closing marker
	end := bytes.Index([]byte(text), []byte("```"))
	if end == -1 {
		return json.Unmarshal([]byte(text), v)
	}

	return json.Unmarshal([]byte(text[:end]), v)
}

// mapPriority converts string priority to domain type.
func mapPriority(s string) advisory.RemediationPriority {
	switch s {
	case "critical":
		return advisory.PriorityCritical
	case "high":
		return advisory.PriorityHigh
	case "medium":
		return advisory.PriorityMedium
	case "low":
		return advisory.PriorityLow
	default:
		return advisory.PriorityMedium
	}
}

// mapRating converts string rating to domain type.
func mapRating(s string) advisory.PostureRating {
	switch s {
	case "excellent":
		return advisory.RatingExcellent
	case "good":
		return advisory.RatingGood
	case "fair":
		return advisory.RatingFair
	case "poor":
		return advisory.RatingPoor
	case "critical":
		return advisory.RatingCritical
	default:
		return advisory.RatingFair
	}
}

// Ensure Adapter implements the interface.
var _ ports.Advisor = (*Adapter)(nil)
