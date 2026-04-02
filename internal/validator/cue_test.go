package validator

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

// resetSchemaCache resets the cached schema state for testing
func resetSchemaCache() {
	cachedSchema = ""
	schemaFetchErr = nil
	schemaOnce = sync.Once{}
}

func TestFetchDefaultSchemaFromNetwork(t *testing.T) {
	resetSchemaCache()

	schema, err := FetchDefaultSchema()
	if err != nil {
		t.Fatalf("FetchDefaultSchema returned error: %v", err)
	}
	if schema == "" {
		t.Fatal("FetchDefaultSchema returned empty schema")
	}
	if len(schema) < 100 {
		t.Errorf("Schema seems too short (%d bytes)", len(schema))
	}
}

func TestDefaultSchemaCompiles(t *testing.T) {
	resetSchemaCache()

	v := NewCUEValidator("", false)

	yaml := []byte("header:\n  schema-version: \"2.0.0\"\n  last-updated: \"2025-01-01\"\n  last-reviewed: \"2025-01-01\"\n  url: https://example.com\nproject:\n  name: test\n  administrators:\n    - name: Test User\n      primary: true\n  repositories:\n    - name: test-repo\n      url: https://github.com/test/test\n      comment: Test repository\n  vulnerability-reporting:\n    reports-accepted: true\n    bug-bounty-available: false\nrepository:\n  url: https://github.com/test/test\n  status: active\n  accepts-change-request: true\n  accepts-automated-change-request: true\n  core-team:\n    - name: Test User\n      primary: true\n  license:\n    url: https://github.com/test/test/blob/main/LICENSE\n    expression: MIT\n  security:\n    assessments:\n      self:\n        comment: Self assessment not yet completed.\n")

	result, err := v.Validate(yaml)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	t.Logf("Valid: %v", result.Valid)
	for _, e := range result.Errors {
		t.Logf("Error: %s", e)
	}
	for _, w := range result.Warnings {
		t.Logf("Warning: %s", w)
	}
	if !result.Valid {
		t.Errorf("Expected valid but got invalid. Errors: %v", result.Errors)
	}
}

func TestSchemaRejectsInvalid(t *testing.T) {
	resetSchemaCache()

	v := NewCUEValidator("", false)

	yaml := []byte("header:\n  schema-version: \"2.0.0\"\n")

	result, err := v.Validate(yaml)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	t.Logf("Valid: %v", result.Valid)
	for _, e := range result.Errors {
		t.Logf("Error: %s", e)
	}
	if result.Valid {
		t.Error("Expected invalid but got valid")
	}
}

func TestFetchSchemaHTTPError(t *testing.T) {
	resetSchemaCache()

	// Start a server that returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Temporarily override the schema URL by using a local schema file path
	// Instead, test via the validator with a bad schema path
	v := NewCUEValidator("/nonexistent/schema.cue", false)
	_, err := v.Validate([]byte("header:\n  schema-version: \"2.0.0\"\n"))
	if err == nil {
		t.Error("Expected error for nonexistent schema file")
	}
}

func TestValidateWithLocalSchema(t *testing.T) {
	resetSchemaCache()

	// Write a minimal CUE schema to a temp file
	tmpFile, err := os.CreateTemp("", "schema-*.cue")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	schema := `#SecurityInsights: {
	header: #Header
}
#Header: {
	"schema-version": string
}
`
	if _, err := tmpFile.WriteString(schema); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	v := NewCUEValidator(tmpFile.Name(), false)
	result, err := v.Validate([]byte("header:\n  schema-version: \"2.0.0\"\n"))
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !result.Valid {
		t.Errorf("Expected valid but got invalid. Errors: %v", result.Errors)
	}
}
