package mcp

import (
	"context"
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
	registry  *engines.Registry
}

// NewServer creates a new VerdictSec MCP server.
func NewServer(cfg *config.Config) *Server {
	srv := mcp.NewServer(mcp.ServerInfo{
		Name:    "verdictsec",
		Version: "1.0.0",
	})

	s := &Server{
		mcpServer: srv,
		config:    cfg,
		registry:  engines.NewDefaultRegistry(),
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

	evalOutput := policyUseCase.Execute(evalInput)

	// Calculate violations and warnings from stats
	violations := evalOutput.Stats.CriticalCount() + evalOutput.Stats.HighCount()
	warnings := evalOutput.Stats.MediumCount()

	result := &PolicyCheckResult{
		Decision:      evalOutput.Decision.String(),
		FailThreshold: pol.Threshold.FailOn.String(),
		WarnThreshold: pol.Threshold.WarnOn.String(),
		Violations:    violations,
		Warnings:      warnings,
		Messages:      make([]string, 0, len(evalOutput.Result.Reasons)),
	}

	for _, msg := range evalOutput.Result.Reasons {
		result.Messages = append(result.Messages, msg)
	}

	return result, nil
}

func (s *Server) handleConfigResource(ctx context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	configJSON := fmt.Sprintf(`{
  "version": "%s",
  "policy": {
    "fail_on": "%s",
    "warn_on": "%s",
    "baseline_mode": "%s"
  },
  "engines": {
    "gosec": {"enabled": %t},
    "govulncheck": {"enabled": %t},
    "gitleaks": {"enabled": %t}
  },
  "baseline": {
    "path": "%s"
  }
}`,
		s.config.Version,
		s.config.Policy.Threshold.FailOn,
		s.config.Policy.Threshold.WarnOn,
		s.config.Policy.BaselineMode,
		s.config.Engines.Gosec.Enabled,
		s.config.Engines.Govulncheck.Enabled,
		s.config.Engines.Gitleaks.Enabled,
		s.config.Baseline.Path,
	)

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     configJSON,
	}, nil
}

func (s *Server) handleBaselineResource(ctx context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	blPath := s.config.Baseline.Path
	if blPath == "" {
		blPath = ".verdict/baseline.json"
	}

	store := baseline.NewStoreWithPath(blPath)
	bl, err := store.Load()
	if err != nil {
		return &mcp.ResourceContent{
			URI:      uri,
			MimeType: "application/json",
			Text:     `{"entries": [], "count": 0}`,
		}, nil
	}

	entriesJSON := "[]"
	if bl.Count() > 0 {
		entries := make([]string, 0, bl.Count())
		for _, entry := range bl.Entries {
			entries = append(entries, fmt.Sprintf(`{"fingerprint": "%s", "rule_id": "%s", "engine_id": "%s"}`,
				entry.Fingerprint, entry.RuleID, entry.EngineID))
		}
		entriesJSON = "[" + join(entries, ",") + "]"
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     fmt.Sprintf(`{"entries": %s, "count": %d}`, entriesJSON, bl.Count()),
	}, nil
}

func (s *Server) handleEnginesResource(ctx context.Context, uri string, params map[string]string) (*mcp.ResourceContent, error) {
	engineStatus := make([]string, 0, 4)

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

		engineStatus = append(engineStatus, fmt.Sprintf(`{"id": "%s", "available": %t, "enabled": %t}`,
			id, available, enabled))
	}

	return &mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     fmt.Sprintf(`{"engines": [%s]}`, join(engineStatus, ",")),
	}, nil
}

func getModeString(strict bool) string {
	if strict {
		return "ci"
	}
	return "local"
}

func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
