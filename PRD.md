Product Requirements Document
Product: VerdictSec - Go Security Assessment CLI

1. Product Vision
   1.1 Problem Statement

Go teams today rely on multiple disconnected tools to assess security:

Static analysis for insecure code patterns

Dependency vulnerability scanners

Secret scanners

SBOM generators for supply-chain transparency

These tools:

operate in isolation

produce noisy, inconsistent output

lack a shared policy model

are difficult to reason about together

often behave differently locally vs CI

As a result:

Developers distrust security tooling

CI pipelines are brittle or overly strict

Security findings accumulate without clear ownership

Supply-chain visibility is incomplete or unusable

1.2 Vision Statement

Build a Go-native, local-first security assessment CLI that deterministically evaluates:

source code security

dependency vulnerabilities

leaked secrets

software supply chain (SBOM)

…under a policy-driven decision model, with clear new-vs-existing signal, CI-safe behavior, and optional AI-assisted understanding.

The tool prioritizes:

determinism

auditability

developer trust

composability

1.3 Guiding Principles (Non-Negotiable)

Deterministic decisions (same inputs → same outputs)

OSS-only scanning engines

Local-first, CI-safe

Policy-driven governance (not tool-driven)

Baselines and suppressions are explicit and auditable

AI is advisory only, never authoritative

Secrets are always redacted

Strong separation of domain vs infrastructure (DDD)

2. Target Users
   Primary Users

Go developers running local scans

Platform engineers maintaining CI pipelines

Security engineers defining policy and governance

Secondary Users

Open-source maintainers

Auditors / compliance reviewers (artifact consumers)

3. Core Use Cases
   Developer (Local)

Run a fast security scan before commit

Understand why a finding exists and how to fix it

Avoid being blocked by legacy issues

CI / Platform

Fail builds only on new or policy-violating findings

Produce machine-readable artifacts (JSON, SARIF, SBOM)

Enforce consistent behavior across repos

Security / Governance

Define security thresholds once

Track exceptions with justification and expiry

Audit findings and decisions after the fact

4. Full Functional Scope (End State)
   4.1 Security Domains Covered
   Source Code Security (SAST)

Insecure coding patterns

Go-specific semantics

Rule-based detection

Dependency Vulnerabilities

Known vulnerabilities in Go modules

Reachability-aware signal

Severity normalization

Secrets Detection

Leaked credentials in source

Working tree, diff, or history modes

Strong redaction and rotation guidance

Supply Chain (SBOM)

Module-level SBOM (dependencies) → cyclonedx-gomod
  - Analyzes go.mod/go.sum for Go module dependencies
  - Best for source code security assessments

Artifact-level SBOM (what is shipped) → syft
  - Scans containers, binaries, and multi-ecosystem artifacts
  - Best for release and deployment security

CycloneDX / SPDX format support

4.2 Decision & Governance

Normalized findings across all engines

Deterministic fingerprinting

Baseline support (“fail only on new findings”)

Suppressions with:

reason

owner

expiry

Explicit policy thresholds

Stable exit-code contract

4.3 Outputs & Integrations

Human-readable console output

JSON for automation

SARIF for code scanning platforms

SBOM artifacts (CycloneDX / SPDX)

Markdown summaries (optional)

4.4 AI & MCP (Optional, Full Scope)

AI features are opt-in and advisory-only:

Explain findings

Suggest remediation patterns

Summarize security posture

Explain SBOM changes and risk

The tool may expose an MCP server providing:

read-only access to findings

policy context

SBOM data

scan diffs

AI cannot:

suppress findings

change severity

affect exit codes

modify policy

5. MVP Scope (First Shippable)
   Included in MVP

CLI with local + CI modes

Engines (6 total):

SAST (gosec)

Advanced Static Analysis (staticcheck)

Dependency vulnerabilities (govulncheck)

Secrets scanning (gitleaks)

Module-level SBOM (cyclonedx-gomod)

Artifact-level SBOM (syft)

Deterministic normalization + fingerprinting

Baseline generation and matching

Suppression handling with expiry

Console + JSON output

Stable exit-code semantics

Fully OSS stack

Originally Not Required for MVP (Now Implemented)

✅ Artifact-level SBOM (Syft)

✅ MCP server

⏳ SARIF normalization (pending)

⏳ AI features (pending)

⏳ Pre-commit hooks (pending)

❌ SaaS components (not planned)

6. Near-Term Extensions (Planned, In-Scope)

✅ Artifact SBOM via container/image scanning (Syft)

✅ MCP server integration

⏳ SBOM diffing between releases

⏳ SARIF output normalization

⏳ AI-assisted explanations

⏳ CI templates (GitHub Actions, GitLab)

⏳ Pre-commit hooks

7. Non-Goals (Explicit)

Runtime protection or enforcement

Auto-remediation or code rewriting

SaaS dashboards or hosted services (initially)

Closed-source or paid scanning engines

AI-driven pass/fail decisions

8. Non-Functional Requirements

Deterministic and reproducible

Fast enough for local use

CI-stable and non-flaky

Secrets never printed or logged

Portable (Linux/macOS)

Clear error semantics (policy vs tooling failure)

Extensible via pluggable engines

9. Success Metrics

Time to first scan < 5 minutes

CI adoption without custom glue scripts

Clear new-vs-existing signal in PRs

Low false-positive complaints with defaults

Zero incidents of secrets leaked by the tool itself

10. Risks & Mitigations
    Risk: Tool noise

Mitigation:

Baselines

Severity normalization

Policy thresholds

Risk: Loss of trust due to AI

Mitigation:

AI is opt-in

Advisory-only

Explicit labeling

Risk: Policy sprawl

Mitigation:

Versioned policies

Required justification

Expiry on suppressions

Risk: Scope creep

Mitigation:

Clear bounded context

Engine abstraction

Explicit non-goals

11. Roadmap (High-Level)

Phase 0: Core CLI, deterministic policy engine ✅ COMPLETE

Phase 1: CI polish, artifact SBOM support ✅ COMPLETE
  - Syft integration for artifact-level SBOM
  - Staticcheck for dead code detection

Phase 2: AI advisory features + MCP 🔄 IN PROGRESS
  - ✅ MCP Server implemented (verdict mcp serve)
  - ⏳ AI advisory features (pending)

Phase 3: Ecosystem integrations (IDE, hooks, templates) 🔄 IN PROGRESS
  - ✅ GitHub Pages landing page
  - ✅ Homebrew tap distribution
  - ⏳ Pre-commit hooks (pending)
  - ⏳ CI templates (pending)

12. Summary

This product is not “another scanner”.

It is a security decision engine for Go codebases:

deterministic

auditable

policy-driven

developer-friendly

extensible without losing trust
