// Package validator provides YAML validation against CUE schemas
package validator

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/errors"
	cueyaml "cuelang.org/go/encoding/yaml"
)

const defaultSchemaURL = "https://raw.githubusercontent.com/ossf/security-insights/main/spec/schema.cue"

var (
	cachedSchema   string
	schemaOnce     sync.Once
	schemaFetchErr error
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

// FetchDefaultSchema fetches the official OSSF CUE schema from GitHub.
// The result is cached after the first successful fetch.
func FetchDefaultSchema() (string, error) {
	schemaOnce.Do(func() {
		resp, err := http.Get(defaultSchemaURL)
		if err != nil {
			schemaFetchErr = fmt.Errorf("failed to fetch schema from %s: %w", defaultSchemaURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			schemaFetchErr = fmt.Errorf("failed to fetch schema from %s: HTTP %d", defaultSchemaURL, resp.StatusCode)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			schemaFetchErr = fmt.Errorf("failed to read schema response: %w", err)
			return
		}

		cachedSchema = string(body)
	})
	return cachedSchema, schemaFetchErr
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
		schema, err := FetchDefaultSchema()
		if err != nil {
			return nil, err
		}
		schemaValue = ctx.CompileString(schema)
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
	if err := unified.Validate(cue.Concrete(true)); err != nil {
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
		"project.documentation",
		"project.vulnerability-reporting.policy",
		"repository.documentation.security-policy",
		"repository.documentation.contributing-guide",
		"repository.release",
	}

	for _, field := range recommendedFields {
		fieldValue := value.LookupPath(cue.ParsePath(field))
		if !fieldValue.Exists() || fieldValue.Err() != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("recommended field '%s' is not set", field))
		}
	}
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
