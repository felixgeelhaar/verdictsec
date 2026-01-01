# Contributing to VerdictSec

Thank you for your interest in contributing to VerdictSec! This document provides guidelines and information about contributing.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Go version, VerdictSec version)
- **Relevant logs** or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Clear title** describing the enhancement
- **Detailed description** of the proposed functionality
- **Use case** explaining why this would be useful
- **Possible implementation** approach (optional)

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** outlined below
3. **Add tests** for new functionality
4. **Ensure all tests pass** (`go test ./...`)
5. **Update documentation** as needed
6. **Write clear commit messages** following conventional commits

## Development Setup

### Prerequisites

```bash
# Go 1.23+
go version

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Building

```bash
git clone https://github.com/felixgeelhaar/verdictsec.git
cd verdictsec

# Build
go build -o verdict ./cmd/verdict
go build -o verdict-mcp ./cmd/verdict-mcp

# Run tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
```

### Running Linters

```bash
golangci-lint run
```

## Coding Standards

### Go Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` for formatting
- Follow [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)

### Architecture

VerdictSec follows hexagonal architecture:

- **Domain Layer** (`internal/domain/`): Business logic, entities, value objects
- **Application Layer** (`internal/application/`): Use cases, port interfaces
- **Infrastructure Layer** (`internal/infrastructure/`): Adapters, external integrations
- **Package Layer** (`pkg/`): Shared utilities

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(engines): add support for semgrep engine
fix(baseline): correctly load fingerprints from file
docs(readme): update installation instructions
test(policy): add tests for threshold validation
```

### Testing

- Write unit tests for all new functionality
- Aim for >80% code coverage
- Use table-driven tests where appropriate
- Mock external dependencies

```go
func TestSomething(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"valid input", "foo", "bar"},
        {"empty input", "", ""},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := DoSomething(tt.input)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Documentation

- Add godoc comments to exported functions and types
- Update README.md for user-facing changes
- Add examples for new features

## Project Structure

```
verdictsec/
├── cmd/                    # CLI entry points
│   ├── verdict/            # Main CLI
│   └── verdict-mcp/        # MCP server
├── internal/               # Private packages
│   ├── domain/             # Business logic
│   ├── application/        # Use cases
│   └── infrastructure/     # Adapters
├── pkg/                    # Public packages
├── docs/                   # Documentation
└── .github/                # GitHub configuration
```

## Review Process

1. All PRs require at least one approval
2. CI must pass (tests, linting, security checks)
3. Coverage should not decrease significantly
4. Documentation must be updated if needed

## Getting Help

- Open a [GitHub Discussion](https://github.com/felixgeelhaar/verdictsec/discussions) for questions
- Join our community channels (if available)
- Review existing issues and PRs for context

## Recognition

Contributors will be recognized in:
- Release notes
- CONTRIBUTORS file (for significant contributions)

Thank you for contributing to VerdictSec!
