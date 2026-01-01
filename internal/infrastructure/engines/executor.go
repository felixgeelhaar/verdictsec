package engines

import (
	"context"
	"sync"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
)

// ExecutionResult holds the result from a single engine execution.
type ExecutionResult struct {
	EngineID    ports.EngineID
	Evidence    ports.Evidence
	RawFindings []ports.RawFinding
	Error       error
}

// Executor runs multiple engines and collects their results.
type Executor struct {
	registry   ports.EngineRegistry
	maxWorkers int
}

// NewExecutor creates a new engine executor.
func NewExecutor(registry ports.EngineRegistry) *Executor {
	return &Executor{
		registry:   registry,
		maxWorkers: 4, // Default parallelism
	}
}

// NewExecutorWithWorkers creates an executor with a specific worker count.
func NewExecutorWithWorkers(registry ports.EngineRegistry, maxWorkers int) *Executor {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	return &Executor{
		registry:   registry,
		maxWorkers: maxWorkers,
	}
}

// ExecuteAll runs all available engines in parallel.
func (e *Executor) ExecuteAll(ctx context.Context, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) []ExecutionResult {
	engines := e.registry.Available()
	return e.executeEngines(ctx, engines, target, configs)
}

// ExecuteByCapability runs engines with a specific capability.
func (e *Executor) ExecuteByCapability(ctx context.Context, capability ports.Capability, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) []ExecutionResult {
	allEngines := e.registry.GetByCapability(capability)

	// Filter to available and enabled engines
	var engines []ports.Engine
	for _, engine := range allEngines {
		if !engine.IsAvailable() {
			continue
		}
		if cfg, ok := configs[engine.ID()]; ok && !cfg.Enabled {
			continue
		}
		engines = append(engines, engine)
	}

	return e.executeEngines(ctx, engines, target, configs)
}

// ExecuteSpecific runs specific engines by ID.
func (e *Executor) ExecuteSpecific(ctx context.Context, engineIDs []ports.EngineID, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) []ExecutionResult {
	var engines []ports.Engine
	for _, id := range engineIDs {
		if engine, ok := e.registry.Get(id); ok {
			if engine.IsAvailable() {
				engines = append(engines, engine)
			}
		}
	}
	return e.executeEngines(ctx, engines, target, configs)
}

// executeEngines runs the given engines in parallel using a worker pool.
func (e *Executor) executeEngines(ctx context.Context, engines []ports.Engine, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) []ExecutionResult {
	if len(engines) == 0 {
		return nil
	}

	// Create channels for work distribution
	jobs := make(chan ports.Engine, len(engines))
	results := make(chan ExecutionResult, len(engines))

	// Determine worker count
	workerCount := e.maxWorkers
	if len(engines) < workerCount {
		workerCount = len(engines)
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.worker(ctx, jobs, results, target, configs)
		}()
	}

	// Send jobs
	for _, engine := range engines {
		jobs <- engine
	}
	close(jobs)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var executionResults []ExecutionResult
	for result := range results {
		executionResults = append(executionResults, result)
	}

	return executionResults
}

// worker processes engine jobs.
func (e *Executor) worker(ctx context.Context, jobs <-chan ports.Engine, results chan<- ExecutionResult, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) {
	for engine := range jobs {
		// Check context cancellation
		select {
		case <-ctx.Done():
			results <- ExecutionResult{
				EngineID: engine.ID(),
				Error:    ctx.Err(),
			}
			continue
		default:
		}

		// Get config for this engine
		config := ports.DefaultEngineConfig()
		if cfg, ok := configs[engine.ID()]; ok {
			config = cfg
		}

		// Skip disabled engines
		if !config.Enabled {
			continue
		}

		// Run the engine
		evidence, findings, err := engine.Run(ctx, target, config)
		results <- ExecutionResult{
			EngineID:    engine.ID(),
			Evidence:    evidence,
			RawFindings: findings,
			Error:       err,
		}
	}
}

// ExecuteSequential runs engines one at a time (useful for debugging).
func (e *Executor) ExecuteSequential(ctx context.Context, engines []ports.Engine, target ports.Target, configs map[ports.EngineID]ports.EngineConfig) []ExecutionResult {
	var results []ExecutionResult

	for _, engine := range engines {
		// Check context cancellation
		select {
		case <-ctx.Done():
			results = append(results, ExecutionResult{
				EngineID: engine.ID(),
				Error:    ctx.Err(),
			})
			continue
		default:
		}

		// Get config for this engine
		config := ports.DefaultEngineConfig()
		if cfg, ok := configs[engine.ID()]; ok {
			config = cfg
		}

		// Skip disabled engines
		if !config.Enabled {
			continue
		}

		// Run the engine
		evidence, findings, err := engine.Run(ctx, target, config)
		results = append(results, ExecutionResult{
			EngineID:    engine.ID(),
			Evidence:    evidence,
			RawFindings: findings,
			Error:       err,
		})
	}

	return results
}

// HasErrors checks if any execution resulted in an error.
func HasErrors(results []ExecutionResult) bool {
	for _, r := range results {
		if r.Error != nil {
			return true
		}
	}
	return false
}

// GetErrors returns all errors from execution results.
func GetErrors(results []ExecutionResult) map[ports.EngineID]error {
	errors := make(map[ports.EngineID]error)
	for _, r := range results {
		if r.Error != nil {
			errors[r.EngineID] = r.Error
		}
	}
	return errors
}

// GetFindings collects all raw findings from execution results.
func GetFindings(results []ExecutionResult) []ports.RawFinding {
	var findings []ports.RawFinding
	for _, r := range results {
		if r.Error == nil {
			findings = append(findings, r.RawFindings...)
		}
	}
	return findings
}

// GroupFindingsByEngine groups findings by their engine ID.
func GroupFindingsByEngine(results []ExecutionResult) map[ports.EngineID][]ports.RawFinding {
	grouped := make(map[ports.EngineID][]ports.RawFinding)
	for _, r := range results {
		if r.Error == nil {
			grouped[r.EngineID] = r.RawFindings
		}
	}
	return grouped
}
