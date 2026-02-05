// Package validator provides YAML validation against CUE schemas
package validator

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/errors"
	cueyaml "cuelang.org/go/encoding/yaml"
)

// CUEValidator validates security-insights.yml against a CUE schema
type CUEValidator struct {
	schemaPath string
	verbose    bool
}

// ValidationResult contains the result of a validation
type ValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
}

// NewCUEValidator creates a new CUEValidator
func NewCUEValidator(schemaPath string, verbose bool) *CUEValidator {
	return &CUEValidator{
		schemaPath: schemaPath,
		verbose:    verbose,
	}
}

// DefaultSchema returns the embedded default CUE schema for security-insights
func DefaultSchema() string {
	return `
// Security Insights Schema v2.0.0
// Based on OSSF Security Insights Specification

#SecurityInsights: {
	"schema-version": string & =~"^[0-9]+\\.[0-9]+\\.[0-9]+$"
	"project-url": string & =~"^https?://"
	contact?: string
	"security-policy"?: string
	"bug-bounty"?: string
	"vulnerability-disclosure"?: string
	"code-of-conduct"?: string
	"mfa-enforced": bool
	"branch-protection": bool
	"code-review": bool
	"code-scanning"?: [...string]
	"dependency-updates"?: [...string]
	fuzzing?: bool
	"audit-history"?: string
	"third-party-dependencies": bool
	license?: string
	"last-reviewed": string & =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
}
`
}

// Validate validates YAML content against the CUE schema
func (v *CUEValidator) Validate(yamlContent []byte) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	ctx := cuecontext.New()

	var schemaValue cue.Value
	if v.schemaPath != "" {
		schemaContent, err := os.ReadFile(v.schemaPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read schema file: %w", err)
		}
		schemaValue = ctx.CompileBytes(schemaContent)
	} else {
		schemaValue = ctx.CompileString(DefaultSchema())
	}

	if schemaValue.Err() != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", schemaValue.Err())
	}

	def := schemaValue.LookupPath(cue.ParsePath("#SecurityInsights"))
	if def.Err() != nil {
		return nil, fmt.Errorf("failed to find #SecurityInsights in schema: %w", def.Err())
	}

	yamlValue, err := cueyaml.Extract("security-insights.yml", yamlContent)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse YAML: %v", err))
		return result, nil
	}

	dataValue := ctx.BuildFile(yamlValue)
	if dataValue.Err() != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to compile YAML: %v", dataValue.Err()))
		return result, nil
	}

	unified := def.Unify(dataValue)
	if err := unified.Validate(); err != nil {
		result.Valid = false
		for _, e := range errors.Errors(err) {
			result.Errors = append(result.Errors, e.Error())
		}
	}

	v.checkWarnings(dataValue, result)

	return result, nil
}

// ValidateFile validates a YAML file
func (v *CUEValidator) ValidateFile(filePath string) (*ValidationResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return v.Validate(content)
}

func (v *CUEValidator) checkWarnings(value cue.Value, result *ValidationResult) {
	recommendedFields := []string{
		"security-policy",
		"vulnerability-disclosure",
		"code-of-conduct",
		"code-scanning",
		"dependency-updates",
	}

	for _, field := range recommendedFields {
		fieldValue := value.LookupPath(cue.ParsePath(field))
		if !fieldValue.Exists() || fieldValue.Err() != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("recommended field '%s' is not set", field))
		}
	}
}

// ValidateWithCLI validates using the cue CLI tool (fallback method)
func ValidateWithCLI(yamlPath, schemaPath string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	_, err := exec.LookPath("cue")
	if err != nil {
		return nil, fmt.Errorf("cue CLI not found: %w", err)
	}

	var cmd *exec.Cmd
	if schemaPath != "" {
		cmd = exec.Command("cue", "vet", yamlPath, schemaPath)
	} else {
		cmd = exec.Command("cue", "vet", yamlPath)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Valid = false
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		result.Errors = append(result.Errors, lines...)
	}

	return result, nil
}

// PrintResult prints the validation result to stdout
func PrintResult(result *ValidationResult) {
	if result.Valid {
		fmt.Println("✅ Validation passed!")
	} else {
		fmt.Println("❌ Validation failed!")
		for _, err := range result.Errors {
			fmt.Printf("  Error: %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("  - %s\n", warn)
		}
	}
}
