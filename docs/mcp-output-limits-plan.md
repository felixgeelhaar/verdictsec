# MCP Token/Output Limit Feature - Implementation Plan

**Issue**: #6 - Add token/output limit for MCP tool responses
**Status**: Planning
**Created**: 2026-01-02

## Problem Statement

Security tool output can be very large when scanning codebases with many findings or generating extensive SBOMs. This creates issues:
- AI assistants have context/token limits
- Large responses slow down interactions
- Excessive data can overwhelm the user

## Proposed Solution

### 1. Configuration Schema Extension

Add `mcp` section to `internal/infrastructure/config/schema.go`:

```go
// MCPConfig defines MCP server settings.
type MCPConfig struct {
    MaxFindings      int    `yaml:"max_findings" json:"max_findings"`           // Max findings to return (default: 50)
    MaxOutputBytes   int    `yaml:"max_output_bytes" json:"max_output_bytes"`   // Approximate byte limit (default: 50000)
    TruncateStrategy string `yaml:"truncate_strategy" json:"truncate_strategy"` // priority, newest, oldest (default: priority)
}
```

**Config file example** (`.verdict/config.yaml`):
```yaml
mcp:
  max_findings: 50
  max_output_bytes: 50000  # ~50KB
  truncate_strategy: priority  # priority | newest | oldest
```

### 2. New Domain Service: TruncationService

Create `internal/domain/services/truncation.go`:

```go
package services

import "github.com/felixgeelhaar/verdictsec/internal/domain/finding"

// TruncationConfig holds truncation settings.
type TruncationConfig struct {
    MaxFindings      int
    MaxOutputBytes   int
    TruncateStrategy TruncateStrategy
}

// TruncateStrategy defines how findings are truncated.
type TruncateStrategy string

const (
    StrategyPriority TruncateStrategy = "priority"  // By severity: CRITICAL > HIGH > MEDIUM > LOW
    StrategyNewest   TruncateStrategy = "newest"    // Most recent first
    StrategyOldest   TruncateStrategy = "oldest"    // Oldest first
)

// TruncationResult holds truncated findings and metadata.
type TruncationResult struct {
    Findings   []*finding.Finding
    Truncated  bool
    TotalCount int
    ShownCount int
    Summary    TruncationSummary
}

// TruncationSummary provides counts by severity.
type TruncationSummary struct {
    BySeverity map[finding.Severity]int
    HiddenBySeverity map[finding.Severity]int
}

// TruncationService handles finding truncation for output limits.
type TruncationService struct{}

// NewTruncationService creates a new truncation service.
func NewTruncationService() *TruncationService {
    return &TruncationService{}
}

// Truncate applies truncation to findings based on config.
func (s *TruncationService) Truncate(findings []*finding.Finding, cfg TruncationConfig) TruncationResult {
    // Implementation:
    // 1. Count total findings by severity
    // 2. Sort findings by strategy (priority = severity desc, newest = time desc, etc.)
    // 3. Take first N findings up to MaxFindings
    // 4. Calculate hidden counts
    // 5. Return TruncationResult with metadata
}
```

### 3. Updated ScanResult Structure

Modify `internal/infrastructure/mcp/server.go` ScanResult:

```go
// ScanResult represents the result of a scan operation.
type ScanResult struct {
    Status        string        `json:"status"`
    TotalCount    int           `json:"total_count"`
    ShownCount    int           `json:"shown_count"`
    Truncated     bool          `json:"truncated"`
    CriticalCount int           `json:"critical_count"`
    HighCount     int           `json:"high_count"`
    MediumCount   int           `json:"medium_count"`
    LowCount      int           `json:"low_count"`
    Findings      []FindingInfo `json:"findings"`
    Duration      string        `json:"duration"`
    // New: Summary of hidden findings when truncated
    TruncationInfo *TruncationInfo `json:"truncation_info,omitempty"`
}

// TruncationInfo provides details about truncated results.
type TruncationInfo struct {
    TotalFindings    int            `json:"total_findings"`
    ShownFindings    int            `json:"shown_findings"`
    HiddenBySeverity map[string]int `json:"hidden_by_severity"`
    Strategy         string         `json:"strategy"`
    Message          string         `json:"message"`
}
```

### 4. Integration Points

#### 4.1 Server Initialization

Add MCP config to Server struct:

```go
type Server struct {
    mcpServer  *mcp.Server
    config     *config.Config
    registry   ports.EngineRegistry
    truncation *services.TruncationService  // New
}
```

#### 4.2 runScan Handler Update

Apply truncation in `runScan()`:

```go
func (s *Server) runScan(ctx context.Context, input ScanInput, forceEngines []ports.EngineID) (*ScanResult, error) {
    // ... existing scan logic ...

    findings := output.Assessment.Findings()

    // Apply truncation if configured
    mcpCfg := s.config.GetMCPConfig()
    truncated := s.truncation.Truncate(findings, services.TruncationConfig{
        MaxFindings:      mcpCfg.MaxFindings,
        MaxOutputBytes:   mcpCfg.MaxOutputBytes,
        TruncateStrategy: services.TruncateStrategy(mcpCfg.TruncateStrategy),
    })

    result := &ScanResult{
        Status:     "completed",
        TotalCount: truncated.TotalCount,
        ShownCount: truncated.ShownCount,
        Truncated:  truncated.Truncated,
        Duration:   time.Since(start).String(),
        Findings:   make([]FindingInfo, 0, len(truncated.Findings)),
    }

    // Add truncation info if truncated
    if truncated.Truncated {
        result.TruncationInfo = &TruncationInfo{
            TotalFindings:    truncated.TotalCount,
            ShownFindings:    truncated.ShownCount,
            HiddenBySeverity: convertSeverityMap(truncated.Summary.HiddenBySeverity),
            Strategy:         string(mcpCfg.TruncateStrategy),
            Message:          fmt.Sprintf("Showing %d of %d findings (sorted by %s)",
                              truncated.ShownCount, truncated.TotalCount, mcpCfg.TruncateStrategy),
        }
    }

    // ... rest of result building ...
}
```

## Files to Create/Modify

### New Files
| File | Purpose |
|------|---------|
| `internal/domain/services/truncation.go` | TruncationService implementation |
| `internal/domain/services/truncation_test.go` | Unit tests for truncation |

### Modified Files
| File | Changes |
|------|---------|
| `internal/infrastructure/config/schema.go` | Add MCPConfig struct and defaults |
| `internal/infrastructure/mcp/server.go` | Integrate truncation, update result types |
| `internal/infrastructure/mcp/server_test.go` | Add truncation tests |

## Implementation Order

1. **Add MCPConfig to schema.go** with defaults
2. **Create TruncationService** in domain/services
3. **Write unit tests** for truncation service
4. **Update MCP server** to use truncation
5. **Add integration tests** for MCP truncation
6. **Update documentation**

## Default Values

| Setting | Default | Rationale |
|---------|---------|-----------|
| `max_findings` | 50 | Reasonable for AI context (~5KB of finding data) |
| `max_output_bytes` | 50000 | ~50KB allows detailed findings without overwhelming |
| `truncate_strategy` | "priority" | Most important (critical/high) findings shown first |

## Example Output

### Normal Response (under limit)
```json
{
  "status": "completed",
  "total_count": 25,
  "shown_count": 25,
  "truncated": false,
  "critical_count": 2,
  "high_count": 8,
  "medium_count": 10,
  "low_count": 5,
  "findings": [...],
  "duration": "2.5s"
}
```

### Truncated Response
```json
{
  "status": "completed",
  "total_count": 150,
  "shown_count": 50,
  "truncated": true,
  "critical_count": 5,
  "high_count": 45,
  "medium_count": 80,
  "low_count": 20,
  "findings": [...],
  "duration": "3.2s",
  "truncation_info": {
    "total_findings": 150,
    "shown_findings": 50,
    "hidden_by_severity": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 80,
      "LOW": 20
    },
    "strategy": "priority",
    "message": "Showing 50 of 150 findings (sorted by priority)"
  }
}
```

## Acceptance Criteria

- [ ] MCPConfig added to config schema with validation
- [ ] TruncationService handles all three strategies
- [ ] Priority strategy sorts CRITICAL > HIGH > MEDIUM > LOW
- [ ] Truncated responses include complete severity counts
- [ ] `truncation_info` only present when `truncated: true`
- [ ] Unit tests cover all truncation strategies
- [ ] Integration tests verify MCP truncation works end-to-end
- [ ] Documentation updated with config examples

## Notes

- The truncation service is a pure domain service with no I/O dependencies
- Byte estimation is approximate (using JSON marshal size)
- Severity counts in result always reflect TOTAL counts, not shown counts
- Hidden counts in `truncation_info` show what was excluded
