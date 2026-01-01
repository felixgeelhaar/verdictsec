# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**VerdictSec** - Go Security Assessment CLI (`verdict`) - a deterministic, policy-driven security tool for Go codebases. Integrates SAST, dependency vulnerabilities, secrets detection, and SBOM generation under a unified decision model.

**Module**: `github.com/felixgeelhaar/verdictsec`

## Build & Development Commands

```bash
# Build
go build -o verdict ./cmd/verdict

# Run tests
go test ./...

# Run single test
go test -run TestName ./path/to/package

# Run with race detector
go test -race ./...

# Lint
golangci-lint run

# Generate mocks (if using mockgen)
go generate ./...
```

## Architecture

**Hexagonal / Clean Architecture with DDD**

```
cmd/verdict/       # CLI entry point, argument parsing, exit-code mapping
internal/
├── application/   # Use cases: RunScan, EvaluatePolicy, WriteBaseline, RenderReport
├── domain/        # Pure Go, no IO dependencies
│   ├── assessment/    # Assessment aggregate (scan execution + findings + decision)
│   ├── policy/        # Policy aggregate (thresholds, suppressions, gating rules)
│   ├── baseline/      # Baseline aggregate (fingerprint sets, scope matching)
│   ├── finding/       # Finding entity with normalized severity, fingerprint, location
│   └── services/      # NormalizationService, FingerprintService, PolicyEvaluationService, DiffService
└── infrastructure/
    ├── engines/       # Scanner adapters: gosec, govulncheck, gitleaks, cyclonedx-gomod, syft
    ├── writers/       # Console, JSON, SARIF, SBOM, Markdown artifact writers
    ├── config/        # .sec/config.yaml loader
    ├── baseline/      # .sec/baseline.json store
    ├── ai/            # Optional AI adapter (read-only, advisory)
    └── mcp/           # Optional MCP server (read-only domain views)
```

**Dependency Rule**: Inner layers (domain) never import outer layers (infrastructure). All IO goes through interfaces defined in domain/application.

## Domain Model

**Aggregates**:
- `Assessment`: Immutable scan result with findings, decision (PASS|WARN|FAIL|ERROR), and artifacts
- `Policy`: Thresholds, suppressions (require owner/reason/expiry), baseline rules
- `Baseline`: Fingerprint set for "existing" findings, scoped and versioned

**Value Objects**: `Severity`, `Confidence`, `Reachability`, `Fingerprint`, `Location` - all immutable and comparable.

**Key Invariant**: Decision is fully derived from findings + policy. Same inputs always produce same outputs.

## CLI Commands

```bash
verdict scan          # Full scan (all engines)
verdict ci            # CI mode (strict exit codes)
verdict sast          # SAST only
verdict vuln          # Dependency vulnerabilities only
verdict secrets       # Secrets detection only
verdict sbom          # Generate SBOM
verdict baseline write    # Create baseline from current findings
verdict baseline update   # Update existing baseline
verdict policy lint       # Validate policy configuration
```

## Exit Code Contract

| Code | Meaning |
|------|---------|
| 0 | PASS (or WARN in local mode) |
| 1 | FAIL (policy violation) |
| 2 | ERROR (tool/config failure) |

## Engine Integration

Engines implement a common interface and are executed via CLI:

```go
type Engine interface {
    ID() EngineID
    Capabilities() []Capability
    Run(ctx context.Context, target Target, config Config) (Evidence, []RawFinding, error)
}
```

MVP engines: `gosec`, `govulncheck`, `gitleaks`, `cyclonedx-gomod`, `syft`

Engines are version-pinned and output parsed as JSON where possible.

## Configuration

- `.verdict/config.yaml` - Policy, thresholds, engine settings
- `.verdict/baseline.json` - Accepted existing findings (fingerprint-based)

## Testing Strategy

- **Domain tests**: Pure Go, no IO, test aggregates and services directly
- **Golden tests**: Normalization output validation
- **Snapshot tests**: Artifact format verification
- **CLI integration tests**: End-to-end command execution
- **CI contract tests**: Exit codes and artifact generation

## Key Design Decisions

1. **Determinism**: All versions (normalization, fingerprinting, policy) recorded in Assessment metadata
2. **Secrets handling**: Always redacted, never stored raw, never logged
3. **AI is advisory**: Optional, read-only, cannot modify findings/decisions/policy
4. **Baseline matching**: Fingerprint-only, no severity changes bypass baseline
5. **Suppressions**: Require owner, reason, and expiry date
