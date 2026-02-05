// si-gen is a CLI tool for generating security-insights.yml files
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/si-generator/internal/generator"
	"github.com/si-generator/internal/scanner"
	"github.com/si-generator/internal/validator"
	"github.com/si-generator/pkg/model"
	"github.com/spf13/cobra"
)

var (
	// Version information
	version = "0.2.0"
	commit  = "development"
	date    = "unknown"
)

// CLI flags
var (
	outputPath  string
	dryRun      bool
	interactive bool
	token       string
	repoURL     string
	force       bool
	verbose     bool
	inputPath   string
	schemaPath  string
	comment     string
	showEmpty   bool

	// Security practice override flags
	mfaEnforced      *bool
	branchProtection *bool
	codeReview       *bool

	// Assessment override flags
	selfAssessmentURL   string
	selfAssessmentDate  string
	thirdPartyAuditURL  string
	thirdPartyAuditDate string

	// Champion flags
	championName  string
	championEmail string

	// Tool flags
	toolResultsURL string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "si-gen",
		Short: "Generate security-insights.yml for GitHub repositories",
		Long: `si-gen is a CLI tool that generates security-insights.yml files 
for GitHub repositories by scanning local files and GitHub API.

It automatically detects security policies, code scanning tools,
vulnerability reporting, release information, and other security-related configurations.

The output follows the Security Insights Spec 2.0.0 format.`,
	}

	// Generate command
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a security-insights.yml file",
		Long: `Generate a security-insights.yml file by scanning the local repository
and optionally fetching data from the GitHub API.

The generated file follows the Security Insights Spec 2.0.0 format with
header, project, and repository sections.

Examples:
  si-gen generate
  si-gen generate --output .github/security-insights.yml
  si-gen generate --repo-url https://github.com/org/repo
  si-gen generate --token $GITHUB_TOKEN
  si-gen generate --dry-run`,
		RunE: runGenerate,
	}

	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "./security-insights.yml", "Output file path")
	generateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print output to stdout instead of writing to file")
	generateCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Prompt for missing fields interactively")
	generateCmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token (or use GITHUB_TOKEN env var)")
	generateCmd.Flags().StringVarP(&repoURL, "repo-url", "r", "", "Repository URL (auto-detected from git remote if not specified)")
	generateCmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing file")
	generateCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Security practice overrides (useful when API cannot detect or for manual specification)
	mfaEnforced = generateCmd.Flags().Bool("mfa-enforced", false, "Set MFA enforcement to true")
	branchProtection = generateCmd.Flags().Bool("branch-protection", false, "Set branch protection to true")
	codeReview = generateCmd.Flags().Bool("code-review", false, "Set code review requirement to true")
	generateCmd.Flags().StringVar(&comment, "comment", "", "Add a comment to the header section")
	generateCmd.Flags().BoolVar(&showEmpty, "show-empty", false, "Show all fields including empty ones")

	// Assessment overrides
	generateCmd.Flags().StringVar(&selfAssessmentURL, "self-assessment", "", "URL to self-assessment document")
	generateCmd.Flags().StringVar(&selfAssessmentDate, "self-assessment-date", "", "Date of self-assessment (YYYY-MM-DD)")
	generateCmd.Flags().StringVar(&thirdPartyAuditURL, "third-party-audit", "", "URL to third-party audit report")
	generateCmd.Flags().StringVar(&thirdPartyAuditDate, "third-party-audit-date", "", "Date of third-party audit (YYYY-MM-DD)")

	// Champion overrides
	generateCmd.Flags().StringVar(&championName, "champion", "", "Name of security champion")
	generateCmd.Flags().StringVar(&championEmail, "champion-email", "", "Email of security champion")

	// Tool overrides
	generateCmd.Flags().StringVar(&toolResultsURL, "tool-results-url", "", "Base URL for tool results (e.g., https://example.com/release/{version})")

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

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get current working directory as repo root
	repoPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 Scanning repository at %s\n", repoPath)
	}

	// Scan local repository
	localScanner := scanner.NewLocalScanner(repoPath, verbose)
	localData, err := localScanner.Scan()
	if err != nil {
		return fmt.Errorf("failed to scan local repository: %w", err)
	}

	if verbose {
		fmt.Println("✅ Local scan complete")
	}

	// Try to get GitHub data if token is available
	githubToken := token
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	var githubData scanner.GitHubData
	var hasGitHubData bool

	if githubToken != "" || repoURL != "" {
		if verbose {
			fmt.Println("🔌 Fetching data from GitHub API...")
		}

		githubScanner, err := scanner.NewGitHubScanner(githubToken, repoURL, verbose)
		if err != nil {
			if verbose {
				fmt.Printf("⚠️  Could not initialize GitHub scanner: %v\n", err)
			}
		} else {
			githubData, err = githubScanner.Scan(ctx)
			if err != nil {
				if verbose {
					fmt.Printf("⚠️  GitHub API error: %v\n", err)
				}
				// Still set project URL from scanner even if API failed
				githubData.ProjectURL = githubScanner.GetRepoURL()
			} else {
				if verbose {
					fmt.Println("✅ GitHub data fetched")
				}
				hasGitHubData = true
			}
		}
	} else if repoURL == "" {
		// Try to detect from git remote
		if githubScanner, err := scanner.ScanWithoutAuth("", verbose); err == nil {
			githubData.ProjectURL = githubScanner.GetRepoURL()
		}
	}

	// Build insights
	builder := generator.NewBuilder(verbose)

	var insights model.SecurityInsights
	if hasGitHubData {
		insights = builder.BuildInsights(localData, githubData)
	} else {
		insights = builder.BuildFromLocalOnly(localData, repoURL)
	}

	// Apply CLI overrides
	applySecurityPracticeOverrides(cmd, &insights)
	applyAssessmentOverrides(cmd, &insights)
	applyChampionOverrides(cmd, &insights)
	applyToolResultsOverrides(cmd, &insights)

	// Apply comment if provided
	if comment != "" {
		insights.Header.Comment = comment
	}

	// Interactive mode
	if interactive {
		if err := runInteractiveMode(&insights); err != nil {
			return err
		}
	}

	// Write output
	writer := generator.NewWriter(verbose)
	opts := generator.WriteOptions{
		DryRun:    dryRun,
		Force:     force,
		ShowEmpty: showEmpty,
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

	return nil
}

func runInteractiveMode(insights *model.SecurityInsights) error {
	// TODO: Implement interactive prompts for full spec format
	fmt.Println("⚠️  Interactive mode not yet implemented for full spec format")
	return nil
}

func applySecurityPracticeOverrides(cmd *cobra.Command, insights *model.SecurityInsights) {
	// Check if any override flags were set
	mfaSet := cmd.Flags().Changed("mfa-enforced")
	branchSet := cmd.Flags().Changed("branch-protection")
	codeReviewSet := cmd.Flags().Changed("code-review")

	if !mfaSet && !branchSet && !codeReviewSet {
		return
	}

	// Ensure repository and security sections exist
	if insights.Repository == nil {
		insights.Repository = &model.Repository{}
	}
	if insights.Repository.Security == nil {
		insights.Repository.Security = &model.Security{}
	}
	if insights.Repository.Security.Practices == nil {
		insights.Repository.Security.Practices = &model.SecurityPractices{}
	}

	// Apply overrides
	if mfaSet {
		insights.Repository.Security.Practices.MFAEnforced = *mfaEnforced
	}
	if branchSet {
		insights.Repository.Security.Practices.BranchProtection = *branchProtection
	}
	if codeReviewSet {
		insights.Repository.Security.Practices.CodeReviewRequired = *codeReview
	}
}

func applyAssessmentOverrides(cmd *cobra.Command, insights *model.SecurityInsights) {
	selfURLSet := cmd.Flags().Changed("self-assessment")
	thirdPartyURLSet := cmd.Flags().Changed("third-party-audit")

	if !selfURLSet && !thirdPartyURLSet {
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

	// Apply self-assessment override
	if selfURLSet && selfAssessmentURL != "" {
		insights.Repository.Security.Assessments.Self = &model.Assessment{
			Evidence: selfAssessmentURL,
			Date:     selfAssessmentDate,
			Comment:  "Self-assessment",
		}
	}

	// Apply third-party audit override
	if thirdPartyURLSet && thirdPartyAuditURL != "" {
		insights.Repository.Security.Assessments.ThirdParty = append(
			insights.Repository.Security.Assessments.ThirdParty,
			model.Assessment{
				Evidence: thirdPartyAuditURL,
				Date:     thirdPartyAuditDate,
				Comment:  "Third-party security audit",
			},
		)
	}
}

func applyChampionOverrides(cmd *cobra.Command, insights *model.SecurityInsights) {
	championSet := cmd.Flags().Changed("champion")

	if !championSet || championName == "" {
		return
	}

	// Ensure repository and security sections exist
	if insights.Repository == nil {
		insights.Repository = &model.Repository{}
	}
	if insights.Repository.Security == nil {
		insights.Repository.Security = &model.Security{}
	}

	// Add champion
	champion := model.Person{
		Name:    championName,
		Email:   championEmail,
		Primary: true,
	}
	insights.Repository.Security.Champions = append(insights.Repository.Security.Champions, champion)
}

func applyToolResultsOverrides(cmd *cobra.Command, insights *model.SecurityInsights) {
	if !cmd.Flags().Changed("tool-results-url") || toolResultsURL == "" {
		return
	}

	// Ensure repository and security sections exist
	if insights.Repository == nil || insights.Repository.Security == nil {
		return
	}

	// Add results to all tools
	for i := range insights.Repository.Security.Tools {
		tool := &insights.Repository.Security.Tools[i]
		tool.Results = &model.ToolResults{}

		if tool.Integration != nil && tool.Integration.AdHoc {
			tool.Results.AdHoc = &model.Attestation{
				Name:         fmt.Sprintf("Scheduled %s Scan Results", tool.Type),
				PredicateURI: fmt.Sprintf("https://intoto.%s", tool.Type),
				Location:     toolResultsURL + "#" + tool.Type,
				Comment:      "Replace {version} with the actual version number for the release you want results for.",
			}
		}
		if tool.Integration != nil && tool.Integration.CI {
			tool.Results.CI = &model.Attestation{
				Name:         fmt.Sprintf("PR %s Scan Results", tool.Type),
				PredicateURI: fmt.Sprintf("https://intoto.%s", tool.Type),
				Location:     toolResultsURL + "#" + tool.Type,
				Comment:      "Replace {version} with the actual version number for the release you want results for.",
			}
		}
		if tool.Integration != nil && tool.Integration.Release {
			tool.Results.Release = &model.Attestation{
				Name:         fmt.Sprintf("Release %s Scan Results", tool.Type),
				PredicateURI: fmt.Sprintf("https://intoto.%s", tool.Type),
				Location:     toolResultsURL + "#" + tool.Type,
				Comment:      "Replace {version} with the actual version number for the release you want results for.",
			}
		}
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
