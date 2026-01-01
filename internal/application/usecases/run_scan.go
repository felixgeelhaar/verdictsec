package usecases

import (
	"context"
	"fmt"
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/domain/assessment"
	"github.com/felixgeelhaar/verdictsec/internal/domain/finding"
)

// RunScanInput contains the input for the RunScan use case.
type RunScanInput struct {
	Target     ports.Target
	Config     ports.Config
	Mode       string // "local", "ci"
	Engines    []ports.EngineID
	Parallel   bool
	MaxWorkers int
}

// RunScanOutput contains the result of the RunScan use case.
type RunScanOutput struct {
	Assessment *assessment.Assessment
	Errors     []EngineError
}

// EngineError represents an error from a specific engine.
type EngineError struct {
	EngineID ports.EngineID
	Error    error
}

// RunScanUseCase orchestrates security scanning.
type RunScanUseCase struct {
	registry   ports.EngineRegistry
	normalizer FindingNormalizer
	writer     ports.ArtifactWriter
}

// FindingNormalizer converts raw findings to domain findings.
type FindingNormalizer interface {
	Normalize(engineID ports.EngineID, raw ports.RawFinding) *finding.Finding
}

// NewRunScanUseCase creates a new RunScan use case.
func NewRunScanUseCase(
	registry ports.EngineRegistry,
	normalizer FindingNormalizer,
	writer ports.ArtifactWriter,
) *RunScanUseCase {
	return &RunScanUseCase{
		registry:   registry,
		normalizer: normalizer,
		writer:     writer,
	}
}

// Execute runs the scan.
func (uc *RunScanUseCase) Execute(ctx context.Context, input RunScanInput) (RunScanOutput, error) {
	output := RunScanOutput{
		Assessment: assessment.NewAssessment(input.Target.Path),
		Errors:     []EngineError{},
	}

	// Determine which engines to run
	engines := uc.selectEngines(input)
	if len(engines) == 0 {
		return output, fmt.Errorf("no engines available for scan")
	}

	// Report progress
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Running %d engine(s)...", len(engines)))
	}

	// Run engines
	if input.Parallel && len(engines) > 1 {
		uc.runParallel(ctx, input, engines, &output)
	} else {
		uc.runSequential(ctx, input, engines, &output)
	}

	// Complete the assessment
	output.Assessment.Complete()

	return output, nil
}

// selectEngines determines which engines to run based on input.
func (uc *RunScanUseCase) selectEngines(input RunScanInput) []ports.Engine {
	var engines []ports.Engine

	if len(input.Engines) > 0 {
		// Use specified engines
		for _, id := range input.Engines {
			if engine, ok := uc.registry.Get(id); ok && engine.IsAvailable() {
				if input.Config.IsEngineEnabled(id) {
					engines = append(engines, engine)
				}
			}
		}
	} else {
		// Use all available enabled engines
		for _, engine := range uc.registry.Available() {
			if input.Config.IsEngineEnabled(engine.ID()) {
				engines = append(engines, engine)
			}
		}
	}

	return engines
}

// runSequential runs engines one at a time.
func (uc *RunScanUseCase) runSequential(
	ctx context.Context,
	input RunScanInput,
	engines []ports.Engine,
	output *RunScanOutput,
) {
	for _, engine := range engines {
		select {
		case <-ctx.Done():
			return
		default:
			uc.runEngine(ctx, input, engine, output)
		}
	}
}

// runParallel runs engines concurrently.
func (uc *RunScanUseCase) runParallel(
	ctx context.Context,
	input RunScanInput,
	engines []ports.Engine,
	output *RunScanOutput,
) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Limit concurrency
	maxWorkers := input.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = len(engines)
	}
	sem := make(chan struct{}, maxWorkers)

	for _, engine := range engines {
		wg.Add(1)
		go func(e ports.Engine) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()

				// Create a thread-safe output wrapper
				localOutput := RunScanOutput{
					Assessment: output.Assessment,
					Errors:     []EngineError{},
				}

				uc.runEngine(ctx, input, e, &localOutput)

				// Merge results
				mu.Lock()
				output.Errors = append(output.Errors, localOutput.Errors...)
				mu.Unlock()
			}
		}(engine)
	}

	wg.Wait()
}

// runEngine executes a single engine.
func (uc *RunScanUseCase) runEngine(
	ctx context.Context,
	input RunScanInput,
	engine ports.Engine,
	output *RunScanOutput,
) {
	engineID := engine.ID()
	engineConfig := input.Config.GetEngineConfig(engineID)

	// Report progress
	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("Running %s...", engineID))
	}

	// Create engine run
	run := assessment.NewEngineRun(string(engineID), engine.Version())

	// Execute engine
	evidence, rawFindings, err := engine.Run(ctx, input.Target, engineConfig)
	if err != nil {
		run.Fail(err)
		output.Assessment.AddEngineRun(run)
		output.Errors = append(output.Errors, EngineError{
			EngineID: engineID,
			Error:    err,
		})

		if uc.writer != nil {
			_ = uc.writer.WriteError(fmt.Errorf("%s: %w", engineID, err))
		}
		return
	}

	// Normalize findings
	var findings []*finding.Finding
	for _, raw := range rawFindings {
		f := uc.normalizer.Normalize(engineID, raw)
		if f != nil {
			findings = append(findings, f)
		}
	}

	// Add findings to assessment
	for _, f := range findings {
		output.Assessment.AddFinding(f)
	}

	// Complete engine run
	run.Complete(len(findings))
	output.Assessment.AddEngineRun(run)

	// Store evidence
	_ = evidence // TODO: Store evidence in assessment metadata

	if uc.writer != nil {
		_ = uc.writer.WriteProgress(fmt.Sprintf("%s: found %d findings", engineID, len(findings)))
	}
}

// RunSASTInput contains input for SAST-only scan.
type RunSASTInput struct {
	Target ports.Target
	Config ports.Config
}

// RunSAST runs only SAST engines.
func (uc *RunScanUseCase) RunSAST(ctx context.Context, input RunSASTInput) (RunScanOutput, error) {
	// Get engines with SAST capability
	sastEngines := uc.registry.GetByCapability(ports.CapabilitySAST)
	var engineIDs []ports.EngineID
	for _, e := range sastEngines {
		engineIDs = append(engineIDs, e.ID())
	}

	return uc.Execute(ctx, RunScanInput{
		Target:   input.Target,
		Config:   input.Config,
		Engines:  engineIDs,
		Parallel: true,
	})
}

// RunVulnInput contains input for vulnerability-only scan.
type RunVulnInput struct {
	Target ports.Target
	Config ports.Config
}

// RunVuln runs only vulnerability scanning engines.
func (uc *RunScanUseCase) RunVuln(ctx context.Context, input RunVulnInput) (RunScanOutput, error) {
	vulnEngines := uc.registry.GetByCapability(ports.CapabilityVuln)
	var engineIDs []ports.EngineID
	for _, e := range vulnEngines {
		engineIDs = append(engineIDs, e.ID())
	}

	return uc.Execute(ctx, RunScanInput{
		Target:   input.Target,
		Config:   input.Config,
		Engines:  engineIDs,
		Parallel: true,
	})
}

// RunSecretsInput contains input for secrets-only scan.
type RunSecretsInput struct {
	Target ports.Target
	Config ports.Config
}

// RunSecrets runs only secrets detection engines.
func (uc *RunScanUseCase) RunSecrets(ctx context.Context, input RunSecretsInput) (RunScanOutput, error) {
	secretsEngines := uc.registry.GetByCapability(ports.CapabilitySecrets)
	var engineIDs []ports.EngineID
	for _, e := range secretsEngines {
		engineIDs = append(engineIDs, e.ID())
	}

	return uc.Execute(ctx, RunScanInput{
		Target:   input.Target,
		Config:   input.Config,
		Engines:  engineIDs,
		Parallel: true,
	})
}
