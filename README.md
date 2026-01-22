# VerdictSec

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/felixgeelhaar/verdictsec/actions/workflows/ci.yml/badge.svg)](https://github.com/felixgeelhaar/verdictsec/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-87%25-brightgreen.svg)](https://github.com/felixgeelhaar/verdictsec)
[![Go Report Card](https://goreportcard.com/badge/github.com/felixgeelhaar/verdictsec)](https://goreportcard.com/report/github.com/felixgeelhaar/verdictsec)

**VerdictSec** is a comprehensive security assessment CLI tool for Go projects. It integrates multiple security engines into a unified interface with policy-based enforcement, baseline management, AI-powered analysis, and MCP (Model Context Protocol) integration for AI assistants.

## Features

- **Multi-Engine Security Scanning**
  - **SAST**: Static analysis with [gosec](https://github.com/securego/gosec)
  - **Vulnerability Scanning**: Dependency vulnerabilities with [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  - **Secrets Detection**: Hardcoded secrets with [gitleaks](https://github.com/gitleaks/gitleaks)
  - **SBOM Generation**: Software Bill of Materials with [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) or [syft](https://github.com/anchore/syft)
  - **Dead Code Detection**: Unused code analysis with [staticcheck](https://staticcheck.io/)
  - **License Compliance**: Dependency license checking with [go-licenses](https://github.com/google/go-licenses)
  - **Advanced SAST**: Multi-language analysis with [semgrep](https://semgrep.dev/) (optional)
  - **Container Scanning**: Comprehensive scanning with [trivy](https://trivy.dev/) (optional)

- **Policy-Based Enforcement**
  - Configurable severity thresholds (fail on HIGH, warn on MEDIUM)
  - Baseline management for suppressing known findings
  - Inline suppressions via code comments (`// verdict:ignore`)
  - CI/CD integration with strict mode

- **Interactive Features**
  - **TUI Mode**: Terminal UI for exploring and managing findings
  - **Watch Mode**: Continuous scanning on file changes
  - **Git Diff Mode**: Compare security findings between branches or commits

- **AI-Powered Analysis**
  - Explain findings with detailed context and remediation steps
  - Generate security posture summaries
  - Auto-apply AI-generated fixes with backup/rollback support

- **CI/CD Integration**
  - Strict CI mode with configurable exit codes
  - PR annotations for GitHub, GitLab, and Bitbucket
  - SARIF output for GitHub Code Scanning
  - JSON output for automation pipelines

- **MCP Server Integration**
  - Expose security scanning to AI assistants (Claude, etc.)
  - Tools: `verdict_scan`, `verdict_sast`, `verdict_vuln`, `verdict_secrets`
  - Resources: `verdict://config`, `verdict://baseline`, `verdict://engines`

- **Developer Experience**
  - Colored console output with severity highlighting
  - Shell completions for bash, zsh, fish, and PowerShell
  - Git pre-commit hooks
  - Performance benchmarking
  - Monorepo support

## Installation

### Prerequisites

Ensure the following tools are installed:

```bash
# Core engines (recommended)
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/gitleaks/gitleaks/v8@latest
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# Optional engines
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/google/go-licenses@latest
```

### Install VerdictSec

```bash
go install github.com/felixgeelhaar/verdictsec/cmd/verdict@latest
```

Or via Homebrew:

```bash
brew install felixgeelhaar/tap/verdictsec
```

### Build from Source

```bash
git clone https://github.com/felixgeelhaar/verdictsec.git
cd verdictsec
go build -o verdict ./cmd/verdict
```

## Quick Start

### Initialize Configuration

```bash
# Initialize VerdictSec in your project
verdict init

# This creates:
#   .verdict/config.yaml   - Configuration file
#   .verdict/baseline.json - Empty baseline file
```

### Run a Full Security Scan

```bash
# Scan current directory
verdict scan

# Scan specific path
verdict scan ./myproject

# Scan with different output formats
verdict scan --json              # JSON output
verdict scan --sarif             # SARIF output (GitHub Code Scanning)
verdict scan -o results.json     # Write to file
```

### Run Individual Scans

```bash
# SAST analysis
verdict sast

# Vulnerability scan
verdict vuln

# Secrets detection
verdict secrets

# Generate SBOM
verdict sbom
```

### Interactive TUI Mode

```bash
# Launch interactive terminal UI
verdict tui

# Key bindings:
#   j/k, ↑/↓     Navigate list
#   Enter/Tab    Toggle detail view focus
#   1-4          Filter severity (CRIT, HIGH, MED, LOW)
#   n/e/s        Filter status (new/existing/suppressed)
#   /            Search mode
#   b            Add to baseline
#   ?            Help
#   q            Quit
```

### Watch Mode

```bash
# Watch for file changes and continuously scan
verdict watch

# Or with the scan command
verdict scan --watch

# Custom debounce duration
verdict watch --debounce=1s
```

### Compare Security Between Git Refs

```bash
# Compare branches
verdict diff main..feature

# Compare releases
verdict diff v1.0.0..v1.1.0

# Compare last 5 commits
verdict diff HEAD~5..HEAD

# Only show new findings
verdict diff main..feature --new-only
```

### CI Mode

```bash
# CI mode (strict, fails on warnings)
verdict ci

# Post findings to PR (auto-detects provider)
verdict ci --pr 123

# Explicit provider
verdict ci --pr 123 --provider=github
verdict ci --pr 123 --provider=gitlab
verdict ci --pr 123 --provider=bitbucket
```

### Monorepo Support

```bash
# Scan all Go modules in a monorepo
verdict monorepo

# Scan specific modules only
verdict monorepo --modules=./svc/a,./svc/b

# Group output by module
verdict monorepo --by-module

# Use multiple parallel workers
verdict monorepo --workers=8
```

## Configuration

Create a `.verdict/config.yaml` file in your project:

```yaml
version: "1"

policy:
  threshold:
    fail_on: HIGH      # Fail on HIGH or CRITICAL findings
    warn_on: MEDIUM    # Warn on MEDIUM findings
  baseline_mode: warn  # strict, warn, or off
  inline_suppressions: true  # Allow // verdict:ignore comments

engines:
  gosec:
    enabled: true
    severity: LOW      # Minimum severity to report
    exclude: [G104]    # Rules to exclude
  govulncheck:
    enabled: true
  gitleaks:
    enabled: true
    settings:
      redact: true     # Redact secrets in output
  cyclonedx-gomod:
    enabled: true
  staticcheck:
    enabled: false     # Dead code detection
  syft:
    enabled: false     # Alternative SBOM generator
  trivy:
    enabled: false     # Container/code scanning
  go-licenses:
    enabled: false     # License compliance
  semgrep:
    enabled: false     # Advanced SAST

output:
  format: console      # console, json, or sarif
  verbosity: normal    # quiet, normal, verbose, debug
  color: true

baseline:
  path: .verdict/baseline.json

ai:
  enabled: false
  provider: claude     # claude or openai
  model: ""            # Optional: override default model
  features:
    explain: true      # AI finding explanations
    remediate: true    # AI remediation suggestions
    summarize: true    # AI security summaries
```

## Inline Suppressions

Suppress individual findings using code comments:

```go
// verdict:ignore G104 - intentionally ignoring error for cleanup
defer file.Close()

// verdict:ignore - suppress all findings on next line
password := os.Getenv("DB_PASSWORD")
```

## Baseline Management

Suppress known findings that have been reviewed:

```bash
# Create initial baseline from current scan
verdict baseline write -r "Initial baseline for legacy code"

# Update baseline with new findings
verdict baseline update -r "Added new false positive"

# Prune old entries not seen in 90 days
verdict baseline update -r "Sprint cleanup" --prune 90
```

## AI Features

### Explain Findings

```bash
# Get AI explanation for a finding
verdict explain finding-abc123

# Use specific provider
verdict explain finding-abc123 --provider claude
```

### Security Posture Summary

```bash
# Generate AI summary of security posture
verdict ai summarize

# Summarize specific directory
verdict ai summarize ./myproject

# Check AI configuration status
verdict ai status
```

### Auto-Fix Findings

```bash
# List fixable findings
verdict fix

# Preview fix for a specific finding
verdict fix finding-abc123 --dry-run

# Apply fix (creates backup)
verdict fix finding-abc123

# Rollback last fix
verdict fix --rollback
```

Configure AI in your config:

```yaml
ai:
  enabled: true
  provider: claude
  features:
    explain: true
    remediate: true
    summarize: true
```

Set your API key:

```bash
export ANTHROPIC_API_KEY="your-api-key"
# or
export OPENAI_API_KEY="your-api-key"
```

## Git Hooks

Install pre-commit hooks to catch security issues before commit:

```bash
# Install pre-commit hook
verdict hook install

# With specific engines only
verdict hook install --engines=gosec,gitleaks

# Strict mode (fail on warnings)
verdict hook install --strict

# Check hook status
verdict hook status

# Uninstall hook
verdict hook uninstall
```

To skip the hook temporarily:

```bash
git commit --no-verify
```

## Engine Status

Check which security engines are installed:

```bash
# Show engine status table
verdict engines

# JSON output
verdict engines --json

# Exit with code 1 if engines missing
verdict engines --check
```

## Shell Completions

Generate shell completion scripts:

```bash
# Bash
source <(verdict completion bash)

# Zsh
verdict completion zsh > "${fpath[1]}/_verdict"

# Fish
verdict completion fish > ~/.config/fish/completions/verdict.fish

# PowerShell
verdict completion powershell | Out-String | Invoke-Expression
```

## Benchmarking

Measure scan performance:

```bash
# Run benchmark (5 iterations)
verdict benchmark

# 10 iterations with 2 warmup runs
verdict benchmark -n 10 --warmup 2

# JSON output for CI
verdict benchmark --json

# Only show per-engine breakdown
verdict benchmark --engines-only
```

## MCP Server

Start the MCP server for AI assistant integration:

```bash
# Stdio transport (for Claude Desktop)
verdict mcp serve

# HTTP transport
verdict mcp serve --transport http --http-addr :8080
```

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "verdictsec": {
      "command": "verdict",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `verdict_scan` | Run a full security scan |
| `verdict_sast` | Run SAST analysis |
| `verdict_vuln` | Run vulnerability scan |
| `verdict_secrets` | Run secrets detection |
| `verdict_baseline_add` | Add findings to baseline |
| `verdict_policy_check` | Check policy compliance |

### Available MCP Resources

| Resource | Description |
|----------|-------------|
| `verdict://config` | Current configuration |
| `verdict://baseline` | Current baseline |
| `verdict://engines` | Available engines |

## Policy Validation

Validate your policy configuration:

```bash
# Lint policy configuration
verdict policy lint

# Lint specific config file
verdict policy lint -c custom.yaml
```

## Enterprise Configuration

### Gitleaks Enterprise License

For [Gitleaks Enterprise](https://gitleaks.io/) features:

```yaml
engines:
  gitleaks:
    enabled: true
    settings:
      license_env: GITLEAKS_LICENSE  # References env var
      config: ".gitleaks.toml"       # Optional custom rules
```

### Private Go Modules

For scanning private Go modules with govulncheck:

```yaml
engines:
  govulncheck:
    enabled: true
    settings:
      goprivate_env: GOPRIVATE
      gonoproxy_env: GONOPROXY
      gonosumdb_env: GONOSUMDB
```

## Exit Codes

| Code | Decision | Meaning |
|------|----------|---------|
| 0 | PASS/WARN | No policy violations |
| 1 | FAIL | Policy violation detected |
| 2 | ERROR | Tool or configuration error |

## Output Formats

### Console (Default)

Colored output with severity highlighting and inline code snippets.

### JSON

Machine-readable output for automation:

```bash
verdict scan --json -o results.json
```

### SARIF

Standard format for GitHub Code Scanning integration:

```bash
verdict scan --sarif -o results.sarif
```

Upload to GitHub:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Architecture

VerdictSec follows hexagonal architecture (ports and adapters):

```
cmd/
  verdict/              # CLI (includes MCP server)
internal/
  domain/               # Business logic
    finding/            # Finding entity
    assessment/         # Assessment aggregate
    policy/             # Policy aggregate
    baseline/           # Baseline aggregate
  application/          # Use cases
    ports/              # Port interfaces
    usecases/           # Application services
  infrastructure/       # Adapters
    engines/            # Security engine adapters
    mcp/                # MCP server implementation
    ai/                 # AI provider adapters
    config/             # Configuration loading
    baseline/           # Baseline persistence
    writers/            # Output writers
    tui/                # Terminal UI
    watcher/            # File watcher
    fixer/              # Auto-fix implementation
pkg/                    # Shared utilities
```

## Development

### Prerequisites

- Go 1.23+
- Make (optional)

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run with race detector
go test -race ./...
```

### Code Quality

```bash
# Run linter
golangci-lint run

# Run security scan on self
verdict scan
```

## Command Reference

| Command | Description |
|---------|-------------|
| `verdict scan` | Run full security scan |
| `verdict ci` | CI mode with strict settings |
| `verdict sast` | Run SAST analysis only |
| `verdict vuln` | Run vulnerability scan only |
| `verdict secrets` | Run secrets detection only |
| `verdict sbom` | Generate SBOM |
| `verdict tui` | Interactive terminal UI |
| `verdict watch` | Watch mode for continuous scanning |
| `verdict diff` | Compare findings between git refs |
| `verdict monorepo` | Scan multiple modules in monorepo |
| `verdict init` | Initialize configuration |
| `verdict baseline write` | Create baseline from scan |
| `verdict baseline update` | Update existing baseline |
| `verdict policy lint` | Validate policy configuration |
| `verdict engines` | Show engine status |
| `verdict fix` | Apply AI-generated fixes |
| `verdict explain` | AI explanation of finding |
| `verdict ai summarize` | AI security posture summary |
| `verdict ai status` | Show AI configuration status |
| `verdict hook install` | Install git pre-commit hook |
| `verdict hook uninstall` | Remove pre-commit hook |
| `verdict hook status` | Check hook installation |
| `verdict mcp serve` | Start MCP server |
| `verdict benchmark` | Performance benchmarking |
| `verdict completion` | Generate shell completions |
| `verdict version` | Show version info |

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [gosec](https://github.com/securego/gosec) - Go security checker
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability scanner
- [gitleaks](https://github.com/gitleaks/gitleaks) - Secrets detection
- [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) - SBOM generation
- [staticcheck](https://staticcheck.io/) - Static analysis
- [mcp-go](https://github.com/mark3labs/mcp-go) - MCP protocol implementation
- [bubbletea](https://github.com/charmbracelet/bubbletea) - Terminal UI framework
