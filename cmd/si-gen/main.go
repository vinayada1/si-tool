// si-gen is a CLI tool for generating security-insights.yml files
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vinayada1/si-tool/internal/generator"
	"github.com/vinayada1/si-tool/internal/scanner"
	"github.com/vinayada1/si-tool/internal/validator"
	"github.com/vinayada1/si-tool/internal/wizard"
	"github.com/vinayada1/si-tool/pkg/model"
)

var (
	// Version information
	version = "0.2.0"
	commit  = "development"
	date    = "unknown"
)

// CLI flags
var (
	outputPath string
	dryRun     bool
	token      string
	repoURL    string
	force      bool
	verbose    bool
	inputPath  string
	schemaPath string

	// Assessment override flags (format: URL or URL,YYYY-MM-DD)
	selfAssessment  string
	thirdPartyAudit string

	// Wizard flags
	wizardPort int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "si-gen",
		Short: "Generate security-insights.yml for GitHub repositories",
		Long: `si-gen is a CLI tool that generates security-insights.yml files 
for GitHub repositories by querying the GitHub API.

It automatically detects security policies, code scanning tools,
vulnerability reporting, release information, and other security-related configurations.

The output follows the Security Insights Spec 2.0.0 format.`,
	}

	// Generate command
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a security-insights.yml file",
		Long: `Generate a security-insights.yml file by fetching data from the GitHub API.

A GitHub token is required (via --token flag or GITHUB_TOKEN env var).
The repository URL can be specified with --repo-url or auto-detected from
the current directory's git remote.

The generated file follows the Security Insights Spec 2.0.0 format with
header, project, and repository sections.

Examples:
  si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo
  si-gen generate --token $GITHUB_TOKEN --repo-url https://github.com/org/repo --dry-run
  si-gen generate --token $GITHUB_TOKEN --output .github/security-insights.yml`,
		RunE: runGenerate,
	}

	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "./security-insights.yml", "Output file path")
	generateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print output to stdout instead of writing to file")
	generateCmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (or use GITHUB_TOKEN env var)")
	generateCmd.Flags().StringVarP(&repoURL, "repo-url", "r", "", "Repository URL (auto-detected from git remote if not specified)")
	generateCmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing file")
	generateCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Assessment overrides (format: URL or URL,YYYY-MM-DD)
	generateCmd.Flags().StringVar(&selfAssessment, "self-assessment", "", "Self-assessment URL or URL,YYYY-MM-DD")
	generateCmd.Flags().StringVar(&thirdPartyAudit, "third-party-audit", "", "Third-party audit URL or URL,YYYY-MM-DD")

	// Validate command
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a security-insights.yml file",
		Long: `Validate a security-insights.yml file against the official CUE schema.

Examples:
  si-gen validate --input security-insights.yml
  si-gen validate --input .github/security-insights.yml --schema custom-schema.cue`,
		RunE: runValidate,
	}

	validateCmd.Flags().StringVarP(&inputPath, "input", "i", "./security-insights.yml", "Input file to validate")
	validateCmd.Flags().StringVarP(&schemaPath, "schema", "s", "", "Custom CUE schema file (optional)")
	validateCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("si-gen version %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
		},
	}

	// Wizard command
	wizardCmd := &cobra.Command{
		Use:   "wizard",
		Short: "Launch a web-based wizard to generate security-insights.yml",
		Long: `Launch an interactive web-based wizard that scans a GitHub repository,
pre-populates all fields, and lets you review and edit before generating.

A GitHub token is required (via --token flag or GITHUB_TOKEN env var).

Examples:
  si-gen wizard --token $GITHUB_TOKEN
  si-gen wizard --token $GITHUB_TOKEN --repo-url https://github.com/org/repo
  si-gen wizard --token $GITHUB_TOKEN --port 9090`,
		RunE: runWizard,
	}

	wizardCmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (or use GITHUB_TOKEN env var)")
	wizardCmd.Flags().StringVarP(&repoURL, "repo-url", "r", "", "Repository URL (can also be entered in the UI)")
	wizardCmd.Flags().StringVarP(&outputPath, "output", "o", "./security-insights.yml", "Output file path")
	wizardCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	wizardCmd.Flags().IntVar(&wizardPort, "port", 8899, "Port for the wizard web server")

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(wizardCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Resolve GitHub token
	githubToken := token
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}
	if githubToken == "" {
		return fmt.Errorf("a GitHub token is required: use --token flag or set GITHUB_TOKEN environment variable")
	}

	// Resolve repo URL: use flag or detect from git remote
	targetURL := repoURL
	if targetURL == "" {
		if gs, err := scanner.NewGitHubScanner(githubToken, "", verbose); err == nil {
			targetURL = gs.GetRepoURL()
		}
		if targetURL == "" {
			return fmt.Errorf("could not determine repository URL: use --repo-url flag or run from a git repository")
		}
	}

	if verbose {
		fmt.Printf("🔍 Scanning %s via GitHub API...\n", targetURL)
	}

	githubScanner, err := scanner.NewGitHubScanner(githubToken, targetURL, verbose)
	if err != nil {
		return fmt.Errorf("failed to initialize GitHub scanner: %w", err)
	}

	githubData, err := githubScanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	if verbose {
		fmt.Println("✅ GitHub data fetched")
	}

	// Build insights
	builder := generator.NewBuilder(verbose)
	insights := builder.BuildInsights(githubData)

	// Apply CLI overrides
	applyAssessmentOverrides(cmd, &insights)

	// Write output
	writer := generator.NewWriter(verbose)
	opts := generator.WriteOptions{
		DryRun: dryRun,
		Force:  force,
	}

	// Convert to absolute path
	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		absOutputPath = outputPath
	}

	if err := writer.Write(insights, absOutputPath, opts); err != nil {
		return err
	}

	if !dryRun {
		fmt.Printf("✅ Generated %s\n", absOutputPath)
	}

	// Validate the generated output against CUE schema
	yamlBytes, err := writer.ToYAML(insights)
	if err == nil {
		v := validator.NewCUEValidator(schemaPath, false)
		if result, err := v.Validate(yamlBytes); err == nil && !result.Valid {
			fmt.Fprintf(os.Stderr, "\n⚠️  Schema validation warnings:\n")
			for _, e := range result.Errors {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
		}
	}

	return nil
}

// parseAssessmentFlag parses "URL" or "URL,YYYY-MM-DD" into url and date.
func parseAssessmentFlag(value string) (url, date string) {
	if i := strings.LastIndex(value, ","); i > 0 {
		candidate := value[i+1:]
		// Check if it looks like a date (YYYY-MM-DD)
		if len(candidate) == 10 && candidate[4] == '-' && candidate[7] == '-' {
			return value[:i], candidate
		}
	}
	return value, ""
}

func applyAssessmentOverrides(cmd *cobra.Command, insights *model.SecurityInsights) {
	selfSet := cmd.Flags().Changed("self-assessment")
	thirdPartySet := cmd.Flags().Changed("third-party-audit")

	if !selfSet && !thirdPartySet {
		return
	}

	// Ensure repository and security sections exist
	if insights.Repository == nil {
		insights.Repository = &model.Repository{}
	}
	if insights.Repository.Security == nil {
		insights.Repository.Security = &model.Security{}
	}
	if insights.Repository.Security.Assessments == nil {
		insights.Repository.Security.Assessments = &model.Assessments{}
	}

	if selfSet && selfAssessment != "" {
		url, date := parseAssessmentFlag(selfAssessment)
		insights.Repository.Security.Assessments.Self = &model.Assessment{
			Evidence: url,
			Date:     date,
			Comment:  "Self-assessment",
		}
	}

	if thirdPartySet && thirdPartyAudit != "" {
		url, date := parseAssessmentFlag(thirdPartyAudit)
		insights.Repository.Security.Assessments.ThirdParty = append(
			insights.Repository.Security.Assessments.ThirdParty,
			model.Assessment{
				Evidence: url,
				Date:     date,
				Comment:  "Third-party security audit",
			},
		)
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	if verbose {
		fmt.Printf("🔍 Validating %s\n", inputPath)
	}

	// Check if file exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", inputPath)
	}

	// Create validator
	v := validator.NewCUEValidator(schemaPath, verbose)

	// Validate file
	result, err := v.ValidateFile(inputPath)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Print result
	validator.PrintResult(result)

	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

func runWizard(cmd *cobra.Command, args []string) error {
	// Resolve GitHub token
	githubToken := token
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}
	if githubToken == "" {
		return fmt.Errorf("a GitHub token is required: use --token flag or set GITHUB_TOKEN environment variable")
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		absOutputPath = outputPath
	}

	srv := wizard.NewServer(githubToken, repoURL, absOutputPath, verbose, wizardPort)
	return srv.Start()
}
