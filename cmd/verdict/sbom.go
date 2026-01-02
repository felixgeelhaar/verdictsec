package main

import (
	"context"
	"fmt"
	"os"

	"github.com/felixgeelhaar/verdictsec/internal/application/ports"
	"github.com/felixgeelhaar/verdictsec/internal/application/usecases"
	infrasbom "github.com/felixgeelhaar/verdictsec/internal/infrastructure/sbom"
	"github.com/felixgeelhaar/verdictsec/internal/infrastructure/writers"
	"github.com/spf13/cobra"
)

var (
	sbomDiffJSON     bool
	sbomDiffMarkdown bool
)

// sbomDiffCmd compares two SBOMs
var sbomDiffCmd = &cobra.Command{
	Use:   "diff <base> <target>",
	Short: "Compare two SBOMs and show differences",
	Long: `Compare two SBOM files and show what components were added, removed, or modified.

Supports CycloneDX (cyclonedx-gomod) and Syft JSON formats.
Auto-detects format from file contents.

Output shows:
  - Added components (in target but not in base)
  - Removed components (in base but not in target)
  - Modified components (version or license changes)
  - Version change classification (major, minor, patch)

Examples:
  verdict sbom diff base.json target.json
  verdict sbom diff v1.0.0-sbom.json v2.0.0-sbom.json
  verdict sbom diff base.json target.json --json
  verdict sbom diff base.json target.json --markdown`,
	Args: cobra.ExactArgs(2),
	RunE: runSBOMDiff,
}

func init() {
	sbomDiffCmd.Flags().BoolVar(&sbomDiffJSON, "json", false, "output as JSON")
	sbomDiffCmd.Flags().BoolVar(&sbomDiffMarkdown, "markdown", false, "output as Markdown")

	sbomCmd.AddCommand(sbomDiffCmd)
}

func runSBOMDiff(cmd *cobra.Command, args []string) error {
	basePath := args[0]
	targetPath := args[1]

	// Validate files exist
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return fmt.Errorf("base SBOM file not found: %s", basePath)
	}
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("target SBOM file not found: %s", targetPath)
	}

	// Create loader
	loader := infrasbom.NewLoader()

	// Create writer based on output format
	writerFactory := writers.NewSBOMDiffWriterFactory()
	var writer ports.SBOMDiffWriter

	switch {
	case sbomDiffJSON:
		writer = writerFactory.JSON(os.Stdout, true)
	case sbomDiffMarkdown:
		writer = writerFactory.Markdown(os.Stdout)
	default:
		// Load config to check if colors are enabled
		cfg, err := loadConfig()
		colors := true
		if err == nil && cfg != nil {
			colors = cfg.Output.Color
		}
		writer = writerFactory.Console(os.Stdout, colors)
	}

	// Create use case
	useCase := usecases.NewDiffSBOMUseCase(loader, writer)

	// Execute diff
	input := usecases.DiffSBOMInput{
		BasePath:   basePath,
		TargetPath: targetPath,
	}

	output, err := useCase.Execute(context.Background(), input)
	if err != nil {
		return err
	}

	// If not JSON/Markdown, print summary
	if !sbomDiffJSON && !sbomDiffMarkdown {
		fmt.Println()
		if output.HasChanges() {
			fmt.Println(output.Summary())
		}
	}

	return nil
}
