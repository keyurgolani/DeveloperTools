package validation

import (
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/server"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIValidator_ValidateEndpoints(t *testing.T) {
	// Create a test server
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Log: config.LogConfig{
			Level: "debug",
		},
	}

	logger := logging.New(cfg.Log.Level)

	// Create server with separate metrics registry for testing
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	testServer := server.NewWithMetrics(cfg, logger, metricsInstance)

	// Create validator
	validator, err := NewAPIValidator("", testServer.GetRouter())
	require.NoError(t, err)

	// Mock some basic spec data
	validator.spec = &OpenAPISpec{
		Paths: map[string]PathItem{
			"/health": {
				Get: &Operation{
					Summary: "Health check",
				},
			},
			"/api/v1/status": {
				Get: &Operation{
					Summary: "Service status",
				},
			},
			"/api/v1/crypto/hash": {
				Post: &Operation{
					Summary: "Calculate hash",
				},
			},
		},
	}

	// Validate endpoints
	result := validator.ValidateEndpoints()

	// The validation should pass since these endpoints are implemented
	assert.True(t, result.Valid, "Endpoint validation should pass")
	assert.Empty(t, result.Errors, "Should have no errors")
}

func TestAPIValidator_ValidateResponseFormats(t *testing.T) {
	// Create a test server with custom metrics registry to avoid conflicts
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Log: config.LogConfig{
			Level: "debug",
		},
	}

	logger := logging.New(cfg.Log.Level)
	// Use a custom registry for this test to avoid metric registration conflicts
	testRegistry := prometheus.NewRegistry()
	testMetrics := metrics.NewWithRegistry(testRegistry)
	testServer := server.NewWithMetrics(cfg, logger, testMetrics)

	// Create validator
	validator, err := NewAPIValidator("", testServer.GetRouter())
	require.NoError(t, err)

	// Mock some basic spec data for GET endpoints (easier to test)
	validator.spec = &OpenAPISpec{
		Paths: map[string]PathItem{
			"/health": {
				Get: &Operation{
					Summary: "Health check",
				},
			},
			"/api/v1/status": {
				Get: &Operation{
					Summary: "Service status",
				},
			},
		},
	}

	// Validate response formats
	result := validator.ValidateResponseFormats()

	// Should have some warnings since we're not using the standardized format for all endpoints yet
	assert.NotEmpty(t, result.Warnings, "Should have warnings about response format")
}

func TestAPIValidator_GenerateValidationReport(t *testing.T) {
	// Create a test server
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Log: config.LogConfig{
			Level: "debug",
		},
	}

	logger := logging.New(cfg.Log.Level)

	// Create server with separate metrics registry for testing
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	testServer := server.NewWithMetrics(cfg, logger, metricsInstance)

	// Create validator
	validator, err := NewAPIValidator("", testServer.GetRouter())
	require.NoError(t, err)

	// Generate validation report
	report := validator.GenerateValidationReport()

	// Should have all validation categories
	assert.Contains(t, report, "endpoints")
	assert.Contains(t, report, "responses")
	assert.Contains(t, report, "schemas")

	// Each category should have a result
	for category, result := range report {
		assert.NotNil(t, result, "Category %s should have a result", category)
	}
}

func TestConvertOpenAPIPathToGin(t *testing.T) {
	tests := []struct {
		name        string
		openAPIPath string
		expected    string
	}{
		{
			name:        "simple path",
			openAPIPath: "/api/v1/health",
			expected:    "/api/v1/health",
		},
		{
			name:        "path with parameter",
			openAPIPath: "/api/v1/users/{id}",
			expected:    "/api/v1/users/{id}", // Would need more sophisticated conversion
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertOpenAPIPathToGin(tt.openAPIPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidationPassing(t *testing.T) {
	tests := []struct {
		name     string
		report   map[string]*ValidationResult
		expected bool
	}{
		{
			name: "all passing",
			report: map[string]*ValidationResult{
				"endpoints": {Valid: true},
				"responses": {Valid: true},
				"schemas":   {Valid: true},
			},
			expected: true,
		},
		{
			name: "one failing",
			report: map[string]*ValidationResult{
				"endpoints": {Valid: true},
				"responses": {Valid: false},
				"schemas":   {Valid: true},
			},
			expected: false,
		},
		{
			name: "all failing",
			report: map[string]*ValidationResult{
				"endpoints": {Valid: false},
				"responses": {Valid: false},
				"schemas":   {Valid: false},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationPassing(tt.report)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAPIValidator_LoadSpec(t *testing.T) {
	// Create a test server
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 8080,
		},
		Log: config.LogConfig{
			Level: "debug",
		},
	}

	logger := logging.New(cfg.Log.Level)
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	testServer := server.NewWithMetrics(cfg, logger, metricsInstance)

	// Create validator
	validator, err := NewAPIValidator("", testServer.GetRouter())
	require.NoError(t, err)

	// Test loading spec data
	specData := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /test:
    get:
      summary: Test endpoint
`)

	err = validator.LoadSpec(specData)
	assert.NoError(t, err, "LoadSpec should not return an error")
}

func TestPrintValidationReport(t *testing.T) {
	// Create a test report
	report := map[string]*ValidationResult{
		"endpoints": {
			Valid:    true,
			Errors:   []string{},
			Warnings: []string{"Some warning"},
		},
		"responses": {
			Valid:    false,
			Errors:   []string{"Response format error"},
			Warnings: []string{},
		},
		"schemas": {
			Valid:    true,
			Errors:   []string{},
			Warnings: []string{},
		},
	}

	// This function prints to stdout, so we just test that it doesn't panic
	assert.NotPanics(t, func() {
		PrintValidationReport(report)
	}, "PrintValidationReport should not panic")
}
