# VerdictSec Security Scan Action

Run comprehensive Go security scans with VerdictSec - SAST, vulnerability detection, secrets scanning, and SBOM generation. All security tools are automatically installed and configured.

## Features

- **SAST Analysis**: Static application security testing with gosec
- **Vulnerability Scanning**: Dependency vulnerabilities with govulncheck and trivy
- **Secrets Detection**: Find leaked credentials with gitleaks
- **SBOM Generation**: Software Bill of Materials with cyclonedx-gomod
- **PR Annotations**: Inline review comments on pull requests
- **SARIF Upload**: Integration with GitHub Security tab
- **Baseline Support**: Suppress known/accepted findings

## Quick Start

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write  # Required for SARIF upload
  pull-requests: write    # Required for PR annotations

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: felixgeelhaar/verdictsec/.github/actions/scan@main
        with:
          path: '.'
          output-format: 'sarif'
          upload-sarif: 'true'
```

This will:
1. Run all security engines (gosec, govulncheck, gitleaks, trivy, cyclonedx)
2. Generate SARIF output
3. Upload results to GitHub Security tab (visible under Security → Code scanning alerts)
4. Post inline annotations on pull requests

## Usage Examples

### Basic CI Scan

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
```

### Strict Mode with High Threshold

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    strict: 'true'
    fail-on: 'high'
```

### SAST Only

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    mode: 'sast'
```

### Vulnerability Scan Only

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    mode: 'vuln'
```

### With Baseline (Suppress Known Findings)

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    baseline: '.verdict/baseline.json'
```

### Exclude Specific Engines

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    exclude-engines: 'trivy,cyclonedx-gomod'
```

### PR Annotations with Custom Token

```yaml
- uses: felixgeelhaar/verdictsec/.github/actions/scan@main
  with:
    pr-annotations: 'true'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Upload to GitHub Security Tab (Code Scanning)

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly scan

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run VerdictSec Security Scan
        uses: felixgeelhaar/verdictsec/.github/actions/scan@main
        with:
          output-format: 'sarif'
          output-file: 'verdict-results.sarif'
          upload-sarif: 'true'
          fail-on: 'critical'  # Only fail on critical findings
        continue-on-error: true  # Allow workflow to continue for SARIF upload

      - name: Upload SARIF (fallback)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: verdict-results.sarif
          category: verdictsec
```

Results appear under **Security → Code scanning alerts** in your repository.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `mode` | Scan mode: `scan`, `ci`, `sast`, `vuln`, `secrets` | `ci` |
| `strict` | Enable strict mode (fail on warnings) | `true` |
| `output-format` | Output format: `console`, `json`, `sarif` | `sarif` |
| `output-file` | Output file path | `verdict-results.sarif` |
| `fail-on` | Severity threshold: `critical`, `high`, `medium`, `low` | `high` |
| `engines` | Comma-separated engines to run | (all) |
| `exclude-engines` | Comma-separated engines to exclude | (none) |
| `baseline` | Path to baseline file | (none) |
| `config` | Path to config file | (none) |
| `pr-annotations` | Post findings as PR comments | `true` |
| `upload-sarif` | Upload SARIF to Security tab | `true` |
| `version` | VerdictSec version | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Exit code (0=pass, 1=fail, 2=error) |
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `sarif-file` | Path to SARIF output file |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | PASS - No policy violations |
| 1 | FAIL - Policy violations found |
| 2 | ERROR - Tool or configuration error |

## Included Security Tools

The action automatically installs:

- **gosec** - Go security checker (SAST)
- **govulncheck** - Official Go vulnerability scanner
- **gitleaks** - Secrets and credentials scanner
- **cyclonedx-gomod** - SBOM generator
- **trivy** - Container and filesystem vulnerability scanner

## Configuration

Create `.verdict/config.yaml` for custom settings:

```yaml
engines:
  gosec:
    enabled: true
  govulncheck:
    enabled: true
  gitleaks:
    enabled: true
  trivy:
    enabled: true

policy:
  threshold:
    fail_on: high
    warn_on: medium
```

## License

MIT License - see [LICENSE](../../../LICENSE) for details.
