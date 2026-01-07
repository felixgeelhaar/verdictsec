package advisory

import (
	"encoding/json"
	"time"
)

// PostureRating indicates the overall security posture.
type PostureRating string

const (
	// RatingExcellent - no critical/high issues, strong security practices.
	RatingExcellent PostureRating = "excellent"
	// RatingGood - minor issues present, generally secure.
	RatingGood PostureRating = "good"
	// RatingFair - some medium issues, needs attention.
	RatingFair PostureRating = "fair"
	// RatingPoor - high severity issues present, significant risk.
	RatingPoor PostureRating = "poor"
	// RatingCritical - critical issues present, immediate action required.
	RatingCritical PostureRating = "critical"
)

// CategorySummary summarizes findings in a specific category.
type CategorySummary struct {
	Category    string `json:"category"`
	Count       int    `json:"count"`
	Critical    int    `json:"critical"`
	High        int    `json:"high"`
	Medium      int    `json:"medium"`
	Low         int    `json:"low"`
	TopIssues   string `json:"top_issues,omitempty"`
	Improvement string `json:"improvement,omitempty"`
}

// Trend indicates direction of security posture change.
type Trend string

const (
	TrendImproving Trend = "improving"
	TrendStable    Trend = "stable"
	TrendDeclining Trend = "declining"
)

// PostureSummary is a value object representing an AI-generated summary
// of the overall security posture. It is immutable and advisory-only.
type PostureSummary struct {
	scanID         string
	rating         PostureRating
	score          int // 0-100
	summary        string
	highlights     []string
	concerns       []string
	recommendations []string
	categories     []CategorySummary
	trend          Trend
	trendReason    string
	provider       string
	model          string
	generatedAt    time.Time
}

// PostureSummaryOption is a functional option for creating posture summaries.
type PostureSummaryOption func(*PostureSummary)

// NewPostureSummary creates a new posture summary for a scan.
func NewPostureSummary(
	scanID string,
	rating PostureRating,
	score int,
	summary string,
	provider string,
	model string,
	opts ...PostureSummaryOption,
) *PostureSummary {
	p := &PostureSummary{
		scanID:          scanID,
		rating:          rating,
		score:           score,
		summary:         summary,
		provider:        provider,
		model:           model,
		generatedAt:     time.Now().UTC(),
		highlights:      make([]string, 0),
		concerns:        make([]string, 0),
		recommendations: make([]string, 0),
		categories:      make([]CategorySummary, 0),
		trend:           TrendStable,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Functional options for posture summary creation

// WithHighlights sets the positive highlights.
func WithHighlights(highlights []string) PostureSummaryOption {
	return func(p *PostureSummary) { p.highlights = highlights }
}

// WithConcerns sets the security concerns.
func WithConcerns(concerns []string) PostureSummaryOption {
	return func(p *PostureSummary) { p.concerns = concerns }
}

// WithPostureRecommendations sets the recommendations for improvement.
func WithPostureRecommendations(recs []string) PostureSummaryOption {
	return func(p *PostureSummary) { p.recommendations = recs }
}

// WithCategories sets the category breakdowns.
func WithCategories(cats []CategorySummary) PostureSummaryOption {
	return func(p *PostureSummary) { p.categories = cats }
}

// WithTrend sets the trend information.
func WithTrend(trend Trend, reason string) PostureSummaryOption {
	return func(p *PostureSummary) {
		p.trend = trend
		p.trendReason = reason
	}
}

// Getters - provide immutable access to posture summary fields

// ScanID returns the ID of the scan this summary is for.
func (p *PostureSummary) ScanID() string { return p.scanID }

// Rating returns the overall posture rating.
func (p *PostureSummary) Rating() PostureRating { return p.rating }

// Score returns the numeric security score (0-100).
func (p *PostureSummary) Score() int { return p.score }

// Summary returns the executive summary.
func (p *PostureSummary) Summary() string { return p.summary }

// Highlights returns positive security highlights.
func (p *PostureSummary) Highlights() []string { return p.highlights }

// Concerns returns security concerns.
func (p *PostureSummary) Concerns() []string { return p.concerns }

// Recommendations returns improvement recommendations.
func (p *PostureSummary) Recommendations() []string { return p.recommendations }

// Categories returns category-wise breakdowns.
func (p *PostureSummary) Categories() []CategorySummary { return p.categories }

// Trend returns the posture trend.
func (p *PostureSummary) Trend() Trend { return p.trend }

// TrendReason returns the reason for the trend.
func (p *PostureSummary) TrendReason() string { return p.trendReason }

// Provider returns the AI provider that generated this summary.
func (p *PostureSummary) Provider() string { return p.provider }

// Model returns the model ID used to generate this summary.
func (p *PostureSummary) Model() string { return p.model }

// GeneratedAt returns when this summary was generated.
func (p *PostureSummary) GeneratedAt() time.Time { return p.generatedAt }

// IsAdvisory always returns true - summaries are advisory only.
func (p *PostureSummary) IsAdvisory() bool { return true }

// IsHealthy returns true if the posture is good or excellent.
func (p *PostureSummary) IsHealthy() bool {
	return p.rating == RatingExcellent || p.rating == RatingGood
}

// postureSummaryJSON is the JSON representation of a posture summary.
type postureSummaryJSON struct {
	ScanID          string            `json:"scan_id"`
	Rating          PostureRating     `json:"rating"`
	Score           int               `json:"score"`
	Summary         string            `json:"summary"`
	Highlights      []string          `json:"highlights,omitempty"`
	Concerns        []string          `json:"concerns,omitempty"`
	Recommendations []string          `json:"recommendations,omitempty"`
	Categories      []CategorySummary `json:"categories,omitempty"`
	Trend           Trend             `json:"trend,omitempty"`
	TrendReason     string            `json:"trend_reason,omitempty"`
	Provider        string            `json:"provider"`
	Model           string            `json:"model"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Advisory        bool              `json:"advisory"`
}

// MarshalJSON implements json.Marshaler.
func (p *PostureSummary) MarshalJSON() ([]byte, error) {
	return json.Marshal(postureSummaryJSON{
		ScanID:          p.scanID,
		Rating:          p.rating,
		Score:           p.score,
		Summary:         p.summary,
		Highlights:      p.highlights,
		Concerns:        p.concerns,
		Recommendations: p.recommendations,
		Categories:      p.categories,
		Trend:           p.trend,
		TrendReason:     p.trendReason,
		Provider:        p.provider,
		Model:           p.model,
		GeneratedAt:     p.generatedAt,
		Advisory:        true,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PostureSummary) UnmarshalJSON(data []byte) error {
	var pj postureSummaryJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return err
	}

	p.scanID = pj.ScanID
	p.rating = pj.Rating
	p.score = pj.Score
	p.summary = pj.Summary
	p.highlights = pj.Highlights
	p.concerns = pj.Concerns
	p.recommendations = pj.Recommendations
	p.categories = pj.Categories
	p.trend = pj.Trend
	p.trendReason = pj.TrendReason
	p.provider = pj.Provider
	p.model = pj.Model
	p.generatedAt = pj.GeneratedAt

	if p.highlights == nil {
		p.highlights = make([]string, 0)
	}
	if p.concerns == nil {
		p.concerns = make([]string, 0)
	}
	if p.recommendations == nil {
		p.recommendations = make([]string, 0)
	}
	if p.categories == nil {
		p.categories = make([]CategorySummary, 0)
	}

	return nil
}
