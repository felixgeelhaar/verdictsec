package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/felixgeelhaar/mcp-go"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	domainbaseline "github.com/felixgeelhaar/verdictsec/internal/domain/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
	"github.com/felixgeelhaar/verdictsec/internal/domain/services"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/ai"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
)

// Server wraps the MCP server with VerdictSec functionality.
type Server struct {
	mcpServer  *mcp.Server
	config     *config.Config
	registry   ports.EngineRegistry
	truncation *services.TruncationService
}

// NewServer creates a new VerdictSec MCP server.
func NewServer(cfg *config.Config, version string) *Server {
	return NewServerWithRegistry(cfg, engines.NewDefaultRegistry(), version)
}

// NewServerWithRegistry creates a new VerdictSec MCP server with a custom registry.
// This is primarily used for testing with mock engines.
func NewServerWithRegistry(cfg *config.Config, registry ports.EngineRegistry, version string) *Server {
	if version == "" {
		version = "dev"
	}
	srv := mcp.NewServer(mcp.ServerInfo{
		Name:    "verdictsec",
		Version: version,
		Capabilities: mcp.Capabilities{
			Tools:     true,
			Resources: true,
		},
	})

	s := &Server{
		mcpServer:  srv,
		config:     cfg,
		registry:   registry,
		truncation: services.NewTruncationService(),
	}

	s.registerTools()
	s.registerResources()

	return s
}

// ServeStdio starts the MCP server with stdio transport.
func (s *Server) ServeStdio(ctx context.Context) error {
	return mcp.ServeStdio(ctx, s.mcpServer)
}

// ServeHTTP starts the MCP server with HTTP transport.
func (s *Server) ServeHTTP(ctx context.Context, addr string) error {
	return mcp.ServeHTTP(ctx, s.mcpServer, addr,
		mcp.WithReadTimeout(60*time.Second),
		mcp.WithWriteTimeout(60*time.Second),
	)
}

// registerTools registers all VerdictSec MCP tools.
func (s *Server) registerTools() {
	// verdict_scan - Run a security scan
	s.mcpServer.Tool("verdict_scan").
		Description("Run a security scan on a Go project. Returns findings with severity, location, and remediation advice.").
		Handler(s.handleScan)

	// verdict_sast - Run SAST analysis only
	s.mcpServer.Tool("verdict_sast").
		Description("Run static application security testing (SAST) using gosec.").
		Handler(s.handleSAST)

	// verdict_vuln - Run vulnerability scan only
	s.mcpServer.Tool("verdict_vuln").
		Description("Run dependency vulnerability scanning using govulncheck.").
		Handler(s.handleVuln)

	// verdict_secrets - Run secrets detection only
	s.mcpServer.Tool("verdict_secrets").
		Description("Scan for leaked secrets and credentials using gitleaks.").
		Handler(s.handleSecrets)

	// verdict_baseline_add - Add findings to baseline
	s.mcpServer.Tool("verdict_baseline_add").
		Description("Add current findings to the baseline to suppress them in future scans.").
		Handler(s.handleBaselineAdd)

	// verdict_policy_check - Check policy compliance
	s.mcpServer.Tool("verdict_policy_check").
		Description("Evaluate findings against the configured security policy.").
		Handler(s.handlePolicyCheck)

	// verdict_explain - AI explanation of findings (advisory only)
	s.mcpServer.Tool("verdict_explain").
		Description("Use AI to generate an explanation of a security finding. Advisory only.").
		Handler(s.handleExplain)

	// verdict_remediate - AI remediation suggestions (advisory only)
	s.mcpServer.Tool("verdict_remediate").
		Description("Use AI to generate remediation suggestions for a security finding. Advisory only.").
		Handler(s.handleRemediate)
}

// registerResources registers all VerdictSec MCP resources.
func (s *Server) registerResources() {
	// verdict://config - Current configuration
	s.mcpServer.Resource("verdict://config").
		Name("Configuration").
		Description("Current VerdictSec configuration including policy thresholds and engine settings.").
		MimeType("application/json").
		Handler(s.handleConfigResource)

	// verdict://baseline - Current baseline
	s.mcpServer.Resource("verdict://baseline").
		Name("Baseline").
		Description("Current baseline of suppressed findings.").
		MimeType("application/json").
		Handler(s.handleBaselineResource)

	// verdict://engines - Available engines
	s.mcpServer.Resource("verdict://engines").
		Name("Engines").
		Description("List of available security scanning engines and their status.").
		MimeType("application/json").
		Handler(s.handleEnginesResource)
}

// ScanInput defines the input for scan operations.
type ScanInput struct {
	Path    string   `json:"path" jsonschema:"description=Path to the Go project to scan"`
	Engines []string `json:"engines,omitempty" jsonschema:"description=Specific engines to use (gosec, govulncheck, gitleaks)"`
	Strict  bool     `json:"strict,omitempty" jsonschema:"description=Enable strict mode (fail on any finding above threshold)"`
}

// ScanResult represents the result of a scan operation.
type ScanResult struct {
	Status         string          `json:"status"`
	TotalCount     int             `json:"total_count"`
	ShownCount     int             `json:"shown_count"`
	BaselinedCount int             `json:"baselined_count"`
	Truncated      bool            `json:"truncated"`
	CriticalCount  int             `json:"critical_count"`
	HighCount      int             `json:"high_count"`
	MediumCount    int             `json:"medium_count"`
	LowCount       int             `json:"low_count"`
	Findings       []FindingInfo   `json:"findings"`
	Duration       string          `json:"duration"`
	TruncationInfo *TruncationInfo `json:"truncation_info,omitempty"`
}

// TruncationInfo provides details about truncated results.
type TruncationInfo struct {
	TotalFindings    int            `json:"total_findings"`
	ShownFindings    int            `json:"shown_findings"`
	HiddenBySeverity map[string]int `json:"hidden_by_severity"`
	Strategy         string         `json:"strategy"`
	Message          string         `json:"message"`
}

// FindingInfo represents a single finding in scan results.
type FindingInfo struct {
	ID          string `json:"id"`
	Engine      string `json:"engine"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleScan(ctx context.Context, input ScanInput) (*ScanResult, error) {
	return s.runScan(ctx, input, nil)
}

func (s *Server) handleSAST(ctx context.Context, input ScanInput) (*ScanResult, error) {
	return s.runScan(ctx, input, []ports.EngineID{ports.EngineGosec})
}

func (s *Server) handleVuln(ctx context.Context, input ScanInput) (*ScanResult, error) {
	return s.runScan(ctx, input, []ports.EngineID{ports.EngineGovulncheck})
}

func (s *Server) handleSecrets(ctx context.Context, input ScanInput) (*ScanResult, error) {
	return s.runScan(ctx, input, []ports.EngineID{ports.EngineGitleaks})
}

func (s *Server) runScan(ctx context.Context, input ScanInput, forceEngines []ports.EngineID) (*ScanResult, error) {
	start := time.Now()

	path := input.Path
	if path == "" {
		path = "."
	}

	// Create silent writer for MCP context
	writer := writers.NewSilentWriter()

	// Create normalizer and scan use case
	normalizer := engines.NewCompositeNormalizer()
	scanUseCase := usecases.NewRunScanUseCase(s.registry, normalizer, writer)

	// Determine engines to use
	var engineIDs []ports.EngineID
	if len(forceEngines) > 0 {
		engineIDs = forceEngines
	} else if len(input.Engines) > 0 {
		// Parse engine names dynamically - EngineID is a string type
		for _, e := range input.Engines {
			id := ports.EngineID(e)
			// Verify the engine exists in registry
			if _, ok := s.registry.Get(id); ok {
				engineIDs = append(engineIDs, id)
			}
		}
	} else {
		// Use all enabled engines from registry dynamically
		for _, engine := range s.registry.All() {
			id := engine.ID()
			engineCfg := s.config.EngineConfig(string(id))
			if engineCfg.Enabled {
				engineIDs = append(engineIDs, id)
			}
		}
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(path),
		Config:     s.config.ToPortsConfig(),
		Mode:       getModeString(input.Strict),
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	output, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Get all findings
	allFindings := output.Assessment.Findings()

	// Load baseline and filter out baselined findings
	bl := s.loadBaseline()
	var activeFindings []*finding.Finding
	var baselinedCount int

	for _, f := range allFindings {
		if bl != nil && bl.Contains(f) {
			baselinedCount++
		} else {
			activeFindings = append(activeFindings, f)
		}
	}

	// Apply truncation to active (non-baselined) findings
	mcpCfg := s.config.GetMCPConfig()
	truncResult := s.truncation.Truncate(activeFindings, services.TruncationConfig{
		MaxFindings: mcpCfg.MaxFindings,
		Strategy:    services.TruncateStrategy(mcpCfg.TruncateStrategy),
	})

	// Count severities from active findings only (for accurate totals)
	var criticalCount, highCount, mediumCount, lowCount int
	for _, f := range activeFindings {
		switch f.EffectiveSeverity().String() {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	// Build result with truncated findings
	result := &ScanResult{
		Status:         "completed",
		TotalCount:    truncResult.TotalCount,
		ShownCount:    truncResult.ShownCount,
		BaselinedCount: baselinedCount,
		Truncated:     truncResult.Truncated,
		CriticalCount:  criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		LowCount:      lowCount,
		Duration:      time.Since(start).String(),
		Findings:      make([]FindingInfo, 0, len(truncResult.Findings)),
	}

	// Convert truncated findings to FindingInfo
	for _, f := range truncResult.Findings {
		result.Findings = append(result.Findings, FindingInfo{
			ID:          f.ID(),
			Engine:      f.EngineID(),
			RuleID:      f.RuleID(),
			Severity:    f.EffectiveSeverity().String(),
			Message:     f.Title(),
			File:        f.Location().File(),
			Line:        f.Location().Line(),
			Fingerprint: f.Fingerprint().String(),
		})
	}

	// Add truncation info if truncation occurred
	if truncResult.Truncated {
		hiddenBySeverity := make(map[string]int)
		for sev, count := range truncResult.Summary.HiddenBySeverity {
			if count > 0 {
				hiddenBySeverity[sev.String()] = count
			}
		}

		result.TruncationInfo = &TruncationInfo{
			TotalFindings:    truncResult.TotalCount,
			ShownFindings:    truncResult.ShownCount,
			HiddenBySeverity: hiddenBySeverity,
			Strategy:         mcpCfg.TruncateStrategy,
			Message: fmt.Sprintf("Showing %d of %d findings (sorted by %s)",
				truncResult.ShownCount, truncResult.TotalCount, mcpCfg.TruncateStrategy),
		}
	}

	return result, nil
}

// loadBaseline loads the baseline from the configured path.
// Returns nil if baseline doesn't exist or cannot be loaded.
func (s *Server) loadBaseline() *domainbaseline.Baseline {
	blPath := s.config.Baseline.Path
	if blPath == "" {
		blPath = ".verdict/baseline.json"
	}

	store := baseline.NewStoreWithPath(blPath)
	bl, err := store.Load()
	if err != nil {
		return nil
	}
	return bl
}

// BaselineAddInput defines input for adding to baseline.
type BaselineAddInput struct {
	Path   string `json:"path" jsonschema:"description=Path to the Go project to baseline"`
	Output string `json:"output,omitempty" jsonschema:"description=Output path for baseline file"`
	Reason string `json:"reason" jsonschema:"description=Reason for adding findings to baseline"`
}

// BaselineResult represents the result of a baseline operation.
type BaselineResult struct {
	Status       string `json:"status"`
	Path         string `json:"path"`
	EntriesAdded int    `json:"entries_added"`
	TotalEntries int    `json:"total_entries"`
}

func (s *Server) handleBaselineAdd(ctx context.Context, input BaselineAddInput) (*BaselineResult, error) {
	path := input.Path
	if path == "" {
		path = "."
	}

	// Create silent writer
	writer := writers.NewSilentWriter()

	// Create normalizer and scan use case
	normalizer := engines.NewCompositeNormalizer()
	scanUseCase := usecases.NewRunScanUseCase(s.registry, normalizer, writer)

	// Get enabled engines dynamically from registry
	var engineIDs []ports.EngineID
	for _, engine := range s.registry.All() {
		id := engine.ID()
		engineCfg := s.config.EngineConfig(string(id))
		if engineCfg.Enabled {
			engineIDs = append(engineIDs, id)
		}
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(path),
		Config:     s.config.ToPortsConfig(),
		Mode:       "local",
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Determine baseline path
	blPath := input.Output
	if blPath == "" {
		blPath = s.config.Baseline.Path
		if blPath == "" {
			blPath = ".verdict/baseline.json"
		}
	}

	// Create baseline store and use case
	store := baseline.NewStoreWithPath(blPath)
	baselineUseCase := usecases.NewWriteBaselineUseCase(store, writer)

	// Validate reason
	reason := input.Reason
	if reason == "" {
		reason = "Added via MCP"
	}

	// Write baseline
	writeInput := usecases.WriteBaselineInput{
		Assessment: scanOutput.Assessment,
		Target:     path,
		Path:       blPath,
		Reason:     reason,
	}

	output, err := baselineUseCase.Write(writeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to write baseline: %w", err)
	}

	return &BaselineResult{
		Status:       "created",
		Path:         output.Path,
		EntriesAdded: output.EntriesAdded,
		TotalEntries: output.EntriesAdded,
	}, nil
}

// PolicyCheckInput defines input for policy checking.
type PolicyCheckInput struct {
	Path string `json:"path" jsonschema:"description=Path to the Go project to check"`
}

// PolicyCheckResult represents the result of a policy check.
type PolicyCheckResult struct {
	Decision       string   `json:"decision"`
	FailThreshold  string   `json:"fail_threshold"`
	WarnThreshold  string   `json:"warn_threshold"`
	Violations     int      `json:"violations"`
	Warnings       int      `json:"warnings"`
	BaselinedCount int      `json:"baselined_count"`
	Messages       []string `json:"messages"`
}

func (s *Server) handlePolicyCheck(ctx context.Context, input PolicyCheckInput) (*PolicyCheckResult, error) {
	path := input.Path
	if path == "" {
		path = "."
	}

	// Create silent writer
	writer := writers.NewSilentWriter()

	// Create normalizer and scan use case
	normalizer := engines.NewCompositeNormalizer()
	scanUseCase := usecases.NewRunScanUseCase(s.registry, normalizer, writer)

	// Get enabled engines dynamically from registry
	var engineIDs []ports.EngineID
	for _, engine := range s.registry.All() {
		id := engine.ID()
		engineCfg := s.config.EngineConfig(string(id))
		if engineCfg.Enabled {
			engineIDs = append(engineIDs, id)
		}
	}

	// Execute scan
	scanInput := usecases.RunScanInput{
		Target:     ports.NewTarget(path),
		Config:     s.config.ToPortsConfig(),
		Mode:       "ci",
		Engines:    engineIDs,
		Parallel:   true,
		MaxWorkers: 4,
	}

	scanOutput, err := scanUseCase.Execute(ctx, scanInput)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Load baseline and filter out baselined findings
	bl := s.loadBaseline()
	allFindings := scanOutput.Assessment.Findings()
	var activeFindings []*finding.Finding
	var baselinedCount int

	for _, f := range allFindings {
		if bl != nil && bl.Contains(f) {
			baselinedCount++
		} else {
			activeFindings = append(activeFindings, f)
		}
	}

	// Count violations and warnings from active findings only
	var violations, warnings int
	pol := s.config.ToDomainPolicy()

	for _, f := range activeFindings {
		sev := f.EffectiveSeverity()
		if sev >= pol.Threshold.FailOn {
			violations++
		} else if sev >= pol.Threshold.WarnOn {
			warnings++
		}
	}

	// Determine decision based on active findings
	decision := "PASS"
	if violations > 0 {
		decision = "FAIL"
	} else if warnings > 0 {
		decision = "WARN"
	}

	// Build messages
	var messages []string
	if baselinedCount > 0 {
		messages = append(messages, fmt.Sprintf("%d findings filtered by baseline", baselinedCount))
	}
	if violations > 0 {
		messages = append(messages, fmt.Sprintf("%d findings at or above %s threshold", violations, pol.Threshold.FailOn.String()))
	}
	if warnings > 0 {
		messages = append(messages, fmt.Sprintf("%d findings at %s threshold", warnings, pol.Threshold.WarnOn.String()))
	}
	if len(activeFindings) == 0 && baselinedCount == 0 {
		messages = append(messages, "No security findings detected")
	} else if len(activeFindings) == 0 && baselinedCount > 0 {
		messages = append(messages, "All findings are baselined")
	}

	result := &PolicyCheckResult{
		Decision:       decision,
		FailThreshold:  pol.Threshold.FailOn.String(),
		WarnThreshold:  pol.Threshold.WarnOn.String(),
		Violations:     violations,
		Warnings:       warnings,
		BaselinedCount: baselinedCount,
		Messages:       messages,
	}

	return result, nil
}

// configResourceData represents the config resource structure for JSON marshaling.
type configResourceData struct {
	Version  string               `json:"version"`
	Policy   configPolicyData     `json:"policy"`
	Engines  configEnginesData    `json:"engines"`
	Baseline configBaselineData   `json:"baseline"`
}

type configPolicyData struct {
	FailOn       string `json:"fail_on"`
	WarnOn       string `json:"warn_on"`
	BaselineMode string `json:"baseline_mode"`
}

// configEnginesData is a map of engine ID to status for dynamic engine support
type configEnginesData map[string]configEngineStatus

type configEngineStatus struct {
	Enabled bool `json:"enabled"`
}

type configBaselineData struct {
	Path string `json:"path"`
}

func (s *Server) handleConfigResource(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	// Build engines config dynamically from registry
	enginesData := make(configEnginesData)
	for _, engine := range s.registry.All() {
		id := string(engine.ID())
		engineCfg := s.config.EngineConfig(id)
		enginesData[id] = configEngineStatus{Enabled: engineCfg.Enabled}
	}

	data := configResourceData{
		Version: s.config.Version,
		Policy: configPolicyData{
			FailOn:       s.config.Policy.Threshold.FailOn,
			WarnOn:       s.config.Policy.Threshold.WarnOn,
			BaselineMode: s.config.Policy.BaselineMode,
		},
		Engines: enginesData,
		Baseline: configBaselineData{
			Path: s.config.Baseline.Path,
		},
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     string(jsonBytes),
	}, nil
}

// baselineResourceData represents the baseline resource structure for JSON marshaling.
type baselineResourceData struct {
	Entries []baselineEntryData `json:"entries"`
	Count   int                 `json:"count"`
}

type baselineEntryData struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	EngineID    string `json:"engine_id"`
}

func (s *Server) handleBaselineResource(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	blPath := s.config.Baseline.Path
	if blPath == "" {
		blPath = ".verdict/baseline.json"
	}

	store := baseline.NewStoreWithPath(blPath)
	bl, err := store.Load()
	if err != nil {
		emptyData := baselineResourceData{
			Entries: []baselineEntryData{},
			Count:   0,
		}
		jsonBytes, _ := json.Marshal(emptyData)
		return &mcp.ResourceContent{
			URI:      uri,
			MimeType: "application/json",
			Text:     string(jsonBytes),
		}, nil
	}

	entries := make([]baselineEntryData, 0, bl.Count())
	for _, entry := range bl.GetEntries() {
		entries = append(entries, baselineEntryData{
			Fingerprint: entry.Fingerprint,
			RuleID:      entry.RuleID,
			EngineID:    entry.EngineID,
		})
	}

	data := baselineResourceData{
		Entries: entries,
		Count:   bl.Count(),
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal baseline: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     string(jsonBytes),
	}, nil
}

// enginesResourceData represents the engines resource structure for JSON marshaling.
type enginesResourceData struct {
	Engines []engineStatusData `json:"engines"`
}

type engineStatusData struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
}

func (s *Server) handleEnginesResource(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	// Dynamically get all engines from registry
	allEngines := s.registry.All()
	engineStatus := make([]engineStatusData, 0, len(allEngines))

	for _, engine := range allEngines {
		id := engine.ID()
		engineCfg := s.config.EngineConfig(string(id))

		engineStatus = append(engineStatus, engineStatusData{
			ID:        string(id),
			Available: engine.IsAvailable(),
			Enabled:   engineCfg.Enabled,
		})
	}

	data := enginesResourceData{
		Engines: engineStatus,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal engines: %w", err)
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     string(jsonBytes),
	}, nil
}

func getModeString(strict bool) string {
	if strict {
		return "ci"
	}
	return "local"
}

// ExplainInput defines input for AI explanation.
type ExplainInput struct {
	FindingID   string `json:"finding_id" jsonschema:"description=ID of the finding to explain"`
	RuleID      string `json:"rule_id,omitempty" jsonschema:"description=Rule ID of the finding"`
	Title       string `json:"title,omitempty" jsonschema:"description=Title/message of the finding"`
	Severity    string `json:"severity,omitempty" jsonschema:"description=Severity of the finding"`
	Description string `json:"description,omitempty" jsonschema:"description=Description of the finding"`
	File        string `json:"file,omitempty" jsonschema:"description=File path where the finding was detected"`
	Line        int    `json:"line,omitempty" jsonschema:"description=Line number of the finding"`
}

// ExplainResult represents the result of an AI explanation.
type ExplainResult struct {
	FindingID   string   `json:"finding_id"`
	Summary     string   `json:"summary"`
	Details     string   `json:"details"`
	RiskContext string   `json:"risk_context"`
	References  []string `json:"references"`
	Provider    string   `json:"provider"`
	Model       string   `json:"model"`
	Advisory    bool     `json:"advisory"`
}

func (s *Server) handleExplain(ctx context.Context, input ExplainInput) (*ExplainResult, error) {
	// Check if AI is enabled
	if !s.config.AI.Enabled {
		return nil, fmt.Errorf("AI features are not enabled. Set ai.enabled: true in your config")
	}

	// Create advisor
	advisorConfig := s.config.ToAdvisorConfig()
	advisor := ai.NewAdvisor(advisorConfig)

	if !advisor.IsAvailable() {
		return nil, fmt.Errorf("AI advisor not available. Check your ANTHROPIC_API_KEY environment variable")
	}

	// Create finding from input
	severity := finding.SeverityMedium
	if input.Severity != "" {
		switch input.Severity {
		case "CRITICAL":
			severity = finding.SeverityCritical
		case "HIGH":
			severity = finding.SeverityHigh
		case "MEDIUM":
			severity = finding.SeverityMedium
		case "LOW":
			severity = finding.SeverityLow
		}
	}

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"mcp",
		input.RuleID,
		input.Title,
		severity,
		finding.NewLocationSimple(input.File, input.Line),
		finding.WithDescription(input.Description),
	)

	// Generate explanation
	explanation, err := advisor.Explain(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("failed to generate explanation: %w", err)
	}

	return &ExplainResult{
		FindingID:   input.FindingID,
		Summary:     explanation.Summary(),
		Details:     explanation.Details(),
		RiskContext: explanation.RiskContext(),
		References:  explanation.References(),
		Provider:    explanation.Provider(),
		Model:       explanation.Model(),
		Advisory:    true,
	}, nil
}

// RemediateInput defines input for AI remediation.
type RemediateInput struct {
	FindingID   string `json:"finding_id" jsonschema:"description=ID of the finding to remediate"`
	RuleID      string `json:"rule_id,omitempty" jsonschema:"description=Rule ID of the finding"`
	Title       string `json:"title,omitempty" jsonschema:"description=Title/message of the finding"`
	Severity    string `json:"severity,omitempty" jsonschema:"description=Severity of the finding"`
	Description string `json:"description,omitempty" jsonschema:"description=Description of the finding"`
	File        string `json:"file,omitempty" jsonschema:"description=File path where the finding was detected"`
	Line        int    `json:"line,omitempty" jsonschema:"description=Line number of the finding"`
	IncludeCode bool   `json:"include_code,omitempty" jsonschema:"description=Include code suggestions"`
}

// RemediateResult represents the result of AI remediation suggestions.
type RemediateResult struct {
	FindingID       string   `json:"finding_id"`
	Priority        string   `json:"priority"`
	Summary         string   `json:"summary"`
	Steps           []string `json:"steps"`
	CodeSuggestions []any    `json:"code_suggestions,omitempty"`
	Effort          string   `json:"effort"`
	Impact          string   `json:"impact"`
	References      []string `json:"references"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	Advisory        bool     `json:"advisory"`
}

func (s *Server) handleRemediate(ctx context.Context, input RemediateInput) (*RemediateResult, error) {
	// Check if AI is enabled
	if !s.config.AI.Enabled {
		return nil, fmt.Errorf("AI features are not enabled. Set ai.enabled: true in your config")
	}

	// Create advisor
	advisorConfig := s.config.ToAdvisorConfig()
	advisor := ai.NewAdvisor(advisorConfig)

	if !advisor.IsAvailable() {
		return nil, fmt.Errorf("AI advisor not available. Check your ANTHROPIC_API_KEY environment variable")
	}

	// Create finding from input
	severity := finding.SeverityMedium
	if input.Severity != "" {
		switch input.Severity {
		case "CRITICAL":
			severity = finding.SeverityCritical
		case "HIGH":
			severity = finding.SeverityHigh
		case "MEDIUM":
			severity = finding.SeverityMedium
		case "LOW":
			severity = finding.SeverityLow
		}
	}

	f := finding.NewFinding(
		finding.FindingTypeSAST,
		"mcp",
		input.RuleID,
		input.Title,
		severity,
		finding.NewLocationSimple(input.File, input.Line),
		finding.WithDescription(input.Description),
	)

	// Generate remediation
	opts := ports.RemediationOptions{
		IncludeCode: input.IncludeCode,
	}

	remediation, err := advisor.Remediate(ctx, f, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate remediation: %w", err)
	}

	// Convert code suggestions
	var codeSuggestions []any
	for _, cs := range remediation.CodeSuggestions() {
		codeSuggestions = append(codeSuggestions, cs)
	}

	return &RemediateResult{
		FindingID:       input.FindingID,
		Priority:        string(remediation.Priority()),
		Summary:         remediation.Summary(),
		Steps:           remediation.Steps(),
		CodeSuggestions: codeSuggestions,
		Effort:          remediation.Effort(),
		Impact:          remediation.Impact(),
		References:      remediation.References(),
		Provider:        remediation.Provider(),
		Model:           remediation.Model(),
		Advisory:        true,
	}, nil
}
