package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpTransport string
	mcpHTTPAddr  string
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI assistant integration",
	Long: `VerdictSec MCP (Model Context Protocol) Server.

Exposes security scanning capabilities through the MCP protocol,
enabling AI assistants to perform security assessments.

Tools:
  verdict_scan         - Run a full security scan
  verdict_sast         - Run SAST analysis (gosec)
  verdict_vuln         - Run vulnerability scan (govulncheck)
  verdict_secrets      - Run secrets detection (gitleaks)
  verdict_baseline_add - Add findings to baseline
  verdict_policy_check - Check policy compliance

Resources:
  verdict://config   - Current configuration
  verdict://baseline - Current baseline
  verdict://engines  - Available engines`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long: `Start the VerdictSec MCP server.

Examples:
  verdict mcp serve                     # Start with stdio transport
  verdict mcp serve --transport http    # Start HTTP server
  verdict mcp serve --http-addr :9090   # HTTP on custom port`,
	RunE: runMCPServer,
}

func init() {
	mcpServeCmd.Flags().StringVarP(&mcpTransport, "transport", "t", "stdio", "Transport type: stdio, http")
	mcpServeCmd.Flags().StringVar(&mcpHTTPAddr, "http-addr", ":8080", "HTTP server address (when using http transport)")

	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServer(cmd *cobra.Command, args []string) error {
	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create MCP server
	server := mcp.NewServer(cfg)

	// Start server with selected transport
	switch mcpTransport {
	case "stdio":
		return server.ServeStdio(ctx)
	case "http":
		fmt.Fprintf(os.Stderr, "Starting VerdictSec MCP server on %s\n", mcpHTTPAddr)
		return server.ServeHTTP(ctx, mcpHTTPAddr)
	default:
		return fmt.Errorf("unsupported transport: %s", mcpTransport)
	}
}
