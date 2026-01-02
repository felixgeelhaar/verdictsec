# VerdictSec Examples

This directory contains example configurations for integrating VerdictSec into your development workflow.

## Pre-commit Hooks

### Using pre-commit framework

Copy `.pre-commit-config.yaml` to your repository root:

```bash
cp examples/.pre-commit-config.yaml /path/to/your/repo/.pre-commit-config.yaml
```

Install pre-commit and hooks:

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type pre-push  # Optional: for pre-push hooks
```

### Using standalone hooks

Copy the hook scripts directly:

```bash
cp scripts/hooks/pre-commit /path/to/your/repo/.git/hooks/
cp scripts/hooks/pre-push /path/to/your/repo/.git/hooks/
chmod +x /path/to/your/repo/.git/hooks/pre-commit /path/to/your/repo/.git/hooks/pre-push
```

Or use the installer:

```bash
./scripts/install-hooks.sh /path/to/your/repo
```

## GitHub Actions

### Full security workflow

Copy `github-workflow/security.yml` to your repository:

```bash
mkdir -p /path/to/your/repo/.github/workflows
cp examples/github-workflow/security.yml /path/to/your/repo/.github/workflows/security.yml
```

Or use the template from `.github/templates/verdictsec-security.yml` for a more comprehensive workflow.

### Features

- SARIF upload to GitHub Code Scanning
- Scheduled weekly scans
- PR comments with security status
- Artifact upload for detailed results

## GitLab CI

### Using remote include

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/felixgeelhaar/verdictsec/main/.gitlab/templates/verdictsec.gitlab-ci.yml'
```

### Using local copy

Copy `gitlab-ci/.gitlab-ci.yml` to your repository:

```bash
cp examples/gitlab-ci/.gitlab-ci.yml /path/to/your/repo/.gitlab-ci.yml
```

### Features

- Full scan on main branch and tags
- Lightweight MR checks
- Weekly scheduled scans
- Manual audit job
- SAST report integration

## Configuration

All examples assume VerdictSec is installed via:

```bash
# Homebrew
brew install felixgeelhaar/tap/verdictsec

# Or Go install
go install github.com/felixgeelhaar/verdictsec/cmd/verdict@latest
```

### Policy Configuration

Create `.verdict/config.yaml` in your repository to customize:

```yaml
policy:
  threshold: medium  # minimum severity to fail

engines:
  gosec:
    enabled: true
  govulncheck:
    enabled: true
  gitleaks:
    enabled: true
  staticcheck:
    enabled: true

output:
  format: console
  colors: true
```

### Baseline Management

To accept existing findings and only fail on new issues:

```bash
# Create baseline from current findings
verdict baseline write

# Update baseline with new accepted findings
verdict baseline update
```

The baseline is stored in `.verdict/baseline.json` and should be committed to version control.
