package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/config"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/mcp"
	"github.com/spf13/cobra"
)

var (
	transport  string
	httpAddr   string
	configPath string
)

var rootCmd = &cobra.Command{
	Use:   "verdict-mcp",
	Short: "VerdictSec MCP Server",
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
  verdict://engines  - Available engines

Examples:
  verdict-mcp                     # Start with stdio transport
  verdict-mcp --transport http    # Start HTTP server
  verdict-mcp --http-addr :9090   # HTTP on custom port`,
	RunE: runServer,
}

func init() {
	rootCmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport type: stdio, http")
	rootCmd.Flags().StringVar(&httpAddr, "http-addr", ":8080", "HTTP server address (when using http transport)")
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
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
	switch transport {
	case "stdio":
		return server.ServeStdio(ctx)
	case "http":
		fmt.Fprintf(os.Stderr, "Starting VerdictSec MCP server on %s\n", httpAddr)
		return server.ServeHTTP(ctx, httpAddr)
	default:
		return fmt.Errorf("unsupported transport: %s", transport)
	}
}

func loadConfig() (*config.Config, error) {
	loader := config.NewLoader()

	if configPath != "" {
		return loader.LoadFromFile(configPath)
	}

	// Try to load from default locations
	cfg, err := loader.Load()
	if err != nil {
		// Return default config if no config file found
		return config.DefaultConfig(), nil
	}
	return cfg, nil
}
