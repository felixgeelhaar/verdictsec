# VerdictSec

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/felixgeelhaar/verdictsec/actions/workflows/ci.yml/badge.svg)](https://github.com/felixgeelhaar/verdictsec/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-87%25-brightgreen.svg)](https://github.com/felixgeelhaar/verdictsec)
[![Go Report Card](https://goreportcard.com/badge/github.com/felixgeelhaar/verdictsec)](https://goreportcard.com/report/github.com/felixgeelhaar/verdictsec)

**VerdictSec** is a comprehensive security assessment CLI tool for Go projects. It integrates multiple security engines into a unified interface with policy-based enforcement, baseline management, and AI-assistant integration via MCP (Model Context Protocol).

## Features

- **Multi-Engine Security Scanning**
  - **SAST**: Static analysis with [gosec](https://github.com/securego/gosec)
  - **Vulnerability Scanning**: Dependency vulnerabilities with [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  - **Secrets Detection**: Hardcoded secrets with [gitleaks](https://github.com/gitleaks/gitleaks)
  - **SBOM Generation**: Software Bill of Materials with [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod)

- **Policy-Based Enforcement**
  - Configurable severity thresholds (fail on HIGH, warn on MEDIUM)
  - Baseline management for suppressing known findings
  - CI/CD integration with strict mode

- **MCP Server Integration**
  - Expose security scanning to AI assistants (Claude, etc.)
  - Tools: `verdict_scan`, `verdict_sast`, `verdict_vuln`, `verdict_secrets`
  - Resources: `verdict://config`, `verdict://baseline`, `verdict://engines`

- **Developer-Friendly**
  - Colored console output with severity highlighting
  - JSON output for automation
  - Deterministic fingerprinting for finding deduplication

## Installation

### Prerequisites

Ensure the following tools are installed:

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Install gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

# Install cyclonedx-gomod
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
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

### Run a Full Security Scan

```bash
# Scan current directory
verdict scan

# Scan specific path
verdict scan ./myproject

# Scan with JSON output
verdict scan --json -o results.json
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

### CI Mode (Strict)

```bash
# Fails on any policy violation
verdict ci
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

output:
  format: console      # console or json
  verbosity: normal    # quiet, normal, verbose, debug
  color: true

baseline:
  path: .verdict/baseline.json
```

## Enterprise Configuration

VerdictSec supports enterprise features through secure credential configuration.

### Gitleaks Enterprise License

For [Gitleaks Enterprise](https://gitleaks.io/) features, configure the license via environment variable reference:

```yaml
# .verdict/config.yaml
engines:
  gitleaks:
    enabled: true
    settings:
      license_env: GITLEAKS_LICENSE  # References env var (recommended)
      config: ".gitleaks.toml"       # Optional custom rules
```

Set the environment variable:

```bash
# Local development (.envrc with direnv, or shell profile)
export GITLEAKS_LICENSE="your-enterprise-token"

# CI/CD (GitHub Actions)
env:
  GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

### Private Go Modules

For scanning private Go modules with govulncheck:

```yaml
# .verdict/config.yaml
engines:
  govulncheck:
    enabled: true
    settings:
      goprivate_env: GOPRIVATE      # Reference to GOPRIVATE env var
      gonoproxy_env: GONOPROXY      # Reference to GONOPROXY env var
      gonosumdb_env: GONOSUMDB      # Reference to GONOSUMDB env var
```

```bash
# Local development
export GOPRIVATE="github.com/mycompany/*"
export GONOPROXY="github.com/mycompany/*"
export GONOSUMDB="github.com/mycompany/*"
```

### Custom Engine Configuration

For gitleaks, you can specify a custom configuration file:

```yaml
engines:
  gitleaks:
    settings:
      config: ".gitleaks.toml"      # Custom rules/allowlist
      mode: "git"                   # Scan git history (default: files only)
```

## Baseline Management

Suppress known findings that have been reviewed:

```bash
# Create initial baseline
verdict baseline write -r "Initial baseline for legacy code"

# Update baseline with new findings
verdict baseline update -r "Added new false positive"
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

## Exit Codes

| Code | Decision | Meaning |
|------|----------|---------|
| 0 | PASS/WARN | No policy violations |
| 1 | FAIL | Policy violation detected |
| 2 | ERROR | Tool or configuration error |

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
    config/             # Configuration loading
    baseline/           # Baseline persistence
    writers/            # Output writers
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
```

### Code Quality

```bash
# Run linter
golangci-lint run

# Run security scan on self
verdict scan
```

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
- [mcp-go](https://github.com/mark3labs/mcp-go) - MCP protocol implementation
