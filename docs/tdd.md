Technical Design Document (TDD)
Product: Go Security Assessment CLI

1. Technical Goals

The system must:

Be deterministic and reproducible

Be local-first and CI-safe

Use only open-source scanning engines

Support policy-driven decisions

Cleanly separate domain logic from tooling

Be extensible without breaking baselines or CI contracts

Support optional AI and MCP without affecting core decisions

2. Architectural Style
   Chosen Architecture

Domain-Driven Design (DDD)

Hexagonal / Clean Architecture

Explicit bounded context

Infrastructure as replaceable adapters

Bounded Context

Security Assessment

This context is responsible for:

Executing scans

Normalizing findings

Applying policy

Producing decisions and artifacts

Out of scope:

Runtime protection

Auto-remediation

SaaS persistence

3. High-Level Architecture

Layers:

Interface Layer

CLI commands

Argument parsing

Exit-code mapping

Application Layer

Use cases (scan, baseline, diff, report)

Orchestration of domain + infrastructure

Domain Layer

Aggregates

Value objects

Domain services

Policy evaluation

Infrastructure Layer

Scanner engines

File IO

Artifact writers

AI & MCP adapters

Dependency rule:
Inner layers never depend on outer layers.

4. Domain Model
   4.1 Aggregates
   Assessment (Aggregate Root)

Represents a single scan execution.

Fields:

AssessmentID

Target (repo or artifact)

EngineRuns[]

Findings[] (normalized)

Decision (PASS | WARN | FAIL | ERROR)

Artifacts[]

Metadata (timestamps, versions)

Invariants:

Decision is fully derived from findings + policy

Findings must have stable fingerprints

Assessment is immutable after creation

Policy (Aggregate Root)

Represents security governance rules.

Fields:

Thresholds

Gating rules

Suppressions

Baseline rules

Version

Invariants:

Suppressions require owner, reason, expiry

Policy evaluation is deterministic

Baseline (Aggregate Root)

Represents accepted existing findings.

Fields:

Fingerprint set

Scope

Normalization version

Fingerprint version

Invariants:

Matching is fingerprint-only

Scope must match assessment

4.2 Entities
Finding

FindingID

Type (sast | vuln | secret | sbom_status)

EngineID

RuleID

NormalizedSeverity

EffectiveSeverity

Confidence

Reachability (if applicable)

Location

Fingerprint

EvidenceRefs[]

4.3 Value Objects

Severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)

Confidence (LOW, MEDIUM, HIGH)

Reachability (REACHABLE, NOT_REACHABLE, UNKNOWN)

Fingerprint

Location

EngineID

RuleID

Value objects are immutable and comparable.

5. Domain Services
   NormalizationService

Converts engine-specific outputs into domain Findings

Applies severity and confidence mapping

Assigns fingerprint (versioned)

FingerprintService

Generates stable fingerprints

Applies type-specific canonicalization rules

Never uses timestamps or absolute paths

PolicyEvaluationService

Applies thresholds

Applies suppressions

Applies baseline logic

Produces Decision + reasons

DiffService

Computes new / existing / resolved findings

Detects metadata changes (severity, reachability)

6. Application Layer (Use Cases)
   Primary Commands

RunScan

RunSAST

RunVulnScan

RunSecretsScan

GenerateSBOM

EvaluatePolicy

WriteBaseline

UpdateBaseline

RenderReport

Each command:

Is deterministic

Has no IO logic

Calls infrastructure through interfaces

7. Infrastructure Layer
   7.1 Engine Adapters (Pluggable)

Each engine implements:

ID()

Capabilities()

Run(context, target, config) → Evidence + RawFindings

Engines v1:

gosec - Static Application Security Testing (SAST)
  Detects insecure coding patterns in Go source code

govulncheck - Dependency Vulnerability Scanning
  Identifies known vulnerabilities in Go modules with reachability analysis

gitleaks - Secrets Detection
  Scans for leaked credentials and sensitive data in source files

cyclonedx-gomod - Module-level SBOM Generation
  Generates SBOM from go.mod/go.sum for dependency transparency

syft - Artifact-level SBOM Generation
  Generates SBOM from containers, binaries, and multi-ecosystem artifacts

Engines are:

Executed via CLI invocation

Version-pinned

Parsed via structured output (JSON where possible)

7.2 Artifact Writers

Console renderer

JSON writer

SARIF writer

SBOM writer

Markdown summary writer

All writers consume domain objects only.

7.3 Config Repository

Loads .sec/config.yaml

Validates schema

Resolves defaults

Merges CLI overrides

7.4 Baseline Store

Reads/writes .sec/baseline.json

Performs scope validation

Does not interpret policy

7.5 AI Adapter (Optional)

Reads domain objects

Produces explanations only

Never modifies findings or decisions

7.6 MCP Server (Optional)

Exposes read-only domain views:

findings

policy

baseline diff

SBOMs

No filesystem or engine access

8. CLI Design
   Commands

sec scan

sec ci

sec sast

sec vuln

sec secrets

sec sbom

sec baseline write

sec baseline update

sec policy lint

CLI responsibilities:

Parse args

Load config

Invoke application use cases

Map decision → exit code

9. Exit Code Contract

0 → PASS (or WARN locally)

1 → FAIL (policy violation)

2 → ERROR (tool/config failure)

Exit codes are only derived from:

Domain Decision

Engine execution status

10. Determinism Guarantees

Normalization versioned

Fingerprinting versioned

Policy versioned

Same inputs always produce same outputs

All versions recorded in Assessment metadata.

11. Security Considerations

Secrets always redacted

No raw secret values stored

AI input minimized and opt-in

No automatic network calls unless required

Engine execution sandboxed to process level

12. Performance Considerations

Parallel engine execution where safe

Caching keyed by:

go.sum

config hash

engine versions

Fast path for changed files only (future)

13. Extensibility Model
    Adding a New Engine

Implement Engine interface

Add normalization mapping

No domain changes required

Adding New Policy Rules

Extend Policy aggregate

Update PolicyEvaluationService

No engine changes required

14. Testing Strategy

Domain tests (pure Go, no IO)

Golden tests for normalization

Snapshot tests for artifacts

CLI integration tests

CI contract tests (exit codes + artifacts)

15. Non-Goals (Technical)

No runtime hooks

No background daemon

No auto-fix

No SaaS persistence

No closed-source dependencies

16. Summary

This design produces:

A credible security tool

Deterministic and auditable behavior

Strong separation of concerns

Long-term extensibility

A clean foundation for AI and MCP without compromising trust
