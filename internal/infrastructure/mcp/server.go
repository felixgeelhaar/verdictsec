package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/felixgeelhaar/mcp-go"
	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	"github.com/felixgeelhaar/verdictsec/internal/domain/policy"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/baseline"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/engines"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
)

// Server wraps the MCP server with VerdictSec functionality.
type Server struct {
	mcpServer *mcp.Server
	config    *config.Config
	registry  ports.EngineRegistry
}

// NewServer creates a new VerdictSec MCP server.
func NewServer(cfg *config.Config) *Server {
	return NewServerWithRegistry(cfg, engines.NewDefaultRegistry())
}

// NewServerWithRegistry creates a new VerdictSec MCP server with a custom registry.
// This is primarily used for testing with mock engines.
func NewServerWithRegistry(cfg *config.Config, registry ports.EngineRegistry) *Server {
	srv := mcp.NewServer(mcp.ServerInfo{
		Name:    "verdictsec",
		Version: "1.0.0",
	})

	s := &Server{
		mcpServer: srv,
		config:    cfg,
		registry:  registry,
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
	Status       string         `json:"status"`
	TotalCount   int            `json:"total_count"`
	CriticalCount int           `json:"critical_count"`
	HighCount    int            `json:"high_count"`
	MediumCount  int            `json:"medium_count"`
	LowCount     int            `json:"low_count"`
	Findings     []FindingInfo  `json:"findings"`
	Duration     string         `json:"duration"`
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
		for _, e := range input.Engines {
			switch e {
			case "gosec":
				engineIDs = append(engineIDs, ports.EngineGosec)
			case "govulncheck":
				engineIDs = append(engineIDs, ports.EngineGovulncheck)
			case "gitleaks":
				engineIDs = append(engineIDs, ports.EngineGitleaks)
			}
		}
	} else {
		// Use config defaults
		if s.config.Engines.Gosec.Enabled {
			engineIDs = append(engineIDs, ports.EngineGosec)
		}
		if s.config.Engines.Govulncheck.Enabled {
			engineIDs = append(engineIDs, ports.EngineGovulncheck)
		}
		if s.config.Engines.Gitleaks.Enabled {
			engineIDs = append(engineIDs, ports.EngineGitleaks)
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

	// Convert findings to result format
	findings := output.Assessment.Findings()
	result := &ScanResult{
		Status:     "completed",
		TotalCount: len(findings),
		Duration:   time.Since(start).String(),
		Findings:   make([]FindingInfo, 0, len(findings)),
	}

	for _, f := range findings {
		// Count by severity
		switch f.EffectiveSeverity().String() {
		case "CRITICAL":
			result.CriticalCount++
		case "HIGH":
			result.HighCount++
		case "MEDIUM":
			result.MediumCount++
		case "LOW":
			result.LowCount++
		}

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

	return result, nil
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

	// Get enabled engines
	var engineIDs []ports.EngineID
	if s.config.Engines.Gosec.Enabled {
		engineIDs = append(engineIDs, ports.EngineGosec)
	}
	if s.config.Engines.Govulncheck.Enabled {
		engineIDs = append(engineIDs, ports.EngineGovulncheck)
	}
	if s.config.Engines.Gitleaks.Enabled {
		engineIDs = append(engineIDs, ports.EngineGitleaks)
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
	Decision     string   `json:"decision"`
	FailThreshold string  `json:"fail_threshold"`
	WarnThreshold string  `json:"warn_threshold"`
	Violations   int      `json:"violations"`
	Warnings     int      `json:"warnings"`
	Messages     []string `json:"messages"`
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

	// Get enabled engines
	var engineIDs []ports.EngineID
	if s.config.Engines.Gosec.Enabled {
		engineIDs = append(engineIDs, ports.EngineGosec)
	}
	if s.config.Engines.Govulncheck.Enabled {
		engineIDs = append(engineIDs, ports.EngineGovulncheck)
	}
	if s.config.Engines.Gitleaks.Enabled {
		engineIDs = append(engineIDs, ports.EngineGitleaks)
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

	// Evaluate policy
	policyUseCase := usecases.NewEvaluatePolicyUseCase(writer)

	pol := s.config.ToDomainPolicy()
	evalInput := usecases.EvaluatePolicyInput{
		Assessment: scanOutput.Assessment,
		Policy:     &pol,
		Mode:       policy.ModeCI,
	}

	evalOutput := policyUseCase.Execute(ctx, evalInput)

	// Calculate violations and warnings from stats
	violations := evalOutput.Stats.CriticalCount() + evalOutput.Stats.HighCount()
	warnings := evalOutput.Stats.MediumCount()

	result := &PolicyCheckResult{
		Decision:      evalOutput.Decision.String(),
		FailThreshold: pol.Threshold.FailOn.String(),
		WarnThreshold: pol.Threshold.WarnOn.String(),
		Violations:    violations,
		Warnings:      warnings,
		Messages:      append([]string{}, evalOutput.Result.Reasons...),
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

type configEnginesData struct {
	Gosec       configEngineStatus `json:"gosec"`
	Govulncheck configEngineStatus `json:"govulncheck"`
	Gitleaks    configEngineStatus `json:"gitleaks"`
}

type configEngineStatus struct {
	Enabled bool `json:"enabled"`
}

type configBaselineData struct {
	Path string `json:"path"`
}

func (s *Server) handleConfigResource(_ context.Context, uri string, _ map[string]string) (*mcp.ResourceContent, error) {
	data := configResourceData{
		Version: s.config.Version,
		Policy: configPolicyData{
			FailOn:       s.config.Policy.Threshold.FailOn,
			WarnOn:       s.config.Policy.Threshold.WarnOn,
			BaselineMode: s.config.Policy.BaselineMode,
		},
		Engines: configEnginesData{
			Gosec:       configEngineStatus{Enabled: s.config.Engines.Gosec.Enabled},
			Govulncheck: configEngineStatus{Enabled: s.config.Engines.Govulncheck.Enabled},
			Gitleaks:    configEngineStatus{Enabled: s.config.Engines.Gitleaks.Enabled},
		},
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
	engineStatus := make([]engineStatusData, 0, 4)

	// Check each engine
	for _, id := range []ports.EngineID{ports.EngineGosec, ports.EngineGovulncheck, ports.EngineGitleaks, ports.EngineCycloneDX} {
		_, available := s.registry.Get(id)

		var enabled bool
		switch id {
		case ports.EngineGosec:
			enabled = s.config.Engines.Gosec.Enabled
		case ports.EngineGovulncheck:
			enabled = s.config.Engines.Govulncheck.Enabled
		case ports.EngineGitleaks:
			enabled = s.config.Engines.Gitleaks.Enabled
		case ports.EngineCycloneDX:
			enabled = s.config.Engines.CycloneDX.Enabled
		}

		engineStatus = append(engineStatus, engineStatusData{
			ID:        string(id),
			Available: available,
			Enabled:   enabled,
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
