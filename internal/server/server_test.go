package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dev-utilities/internal/config"
	"dev-utilities/internal/logging"
	"dev-utilities/internal/metrics"
	"dev-utilities/internal/version"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_HealthEndpoints(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	// Create test logger
	logger := logging.New("info")

	// Create server with separate metrics registry for testing
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	server := NewWithMetrics(cfg, logger, metricsInstance)

	tests := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedFields []string
	}{
		{
			name:           "Basic health check",
			endpoint:       "/health",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status", "timestamp", "service"},
		},
		{
			name:           "Liveness probe",
			endpoint:       "/health/live",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status"},
		},
		{
			name:           "Readiness probe",
			endpoint:       "/health/ready",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req, err := http.NewRequest("GET", tt.endpoint, nil)
			require.NoError(t, err)

			// Create response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			server.router.ServeHTTP(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check response body
			var response map[string]interface{}
			err = json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)

			// Check expected fields are present
			for _, field := range tt.expectedFields {
				assert.Contains(t, response, field, "Response should contain field: %s", field)
			}
		})
	}
}

func TestServer_StatusEndpoint(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	// Create test logger
	logger := logging.New("info")

	// Create server with separate metrics registry for testing
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	server := NewWithMetrics(cfg, logger, metricsInstance)

	// Create request
	req, err := http.NewRequest("GET", "/api/v1/status", nil)
	require.NoError(t, err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Serve the request
	server.router.ServeHTTP(rr, req)

	// Check status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check response body
	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check expected fields
	assert.Equal(t, version.ServiceName, response["service"])
	assert.Equal(t, version.Version, response["version"])
	assert.Equal(t, "running", response["status"])
}

func TestServer_New(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	logger := logging.New("info")
	
	// Use NewWithMetrics to avoid registry conflicts
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	server := NewWithMetrics(cfg, logger, metricsInstance)

	assert.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.Equal(t, logger, server.logger)
	assert.NotNil(t, server.router)
}

func TestServer_GetRouter(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	logger := logging.New("info")
	
	// Use NewWithMetrics to avoid registry conflicts
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	server := NewWithMetrics(cfg, logger, metricsInstance)

	router := server.GetRouter()
	assert.NotNil(t, router)
	assert.Equal(t, server.router, router)
}

func TestServer_ServeHTTP(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		Log: config.LogConfig{
			Level: "info",
		},
	}

	logger := logging.New("info")
	
	// Use NewWithMetrics to avoid registry conflicts
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	server := NewWithMetrics(cfg, logger, metricsInstance)

	// Create a test request
	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(t, err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Test ServeHTTP method
	server.ServeHTTP(rr, req)

	// Should get a successful response
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestSanitizeQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "safe query parameters",
			query:    "name=john&age=30&city=newyork",
			expected: "name=john&age=30&city=newyork",
		},
		{
			name:     "query with password",
			query:    "username=john&password=secret123",
			expected: "[REDACTED]",
		},
		{
			name:     "query with api_key",
			query:    "api_key=abc123&data=test",
			expected: "[REDACTED]",
		},
		{
			name:     "query with token",
			query:    "token=bearer123&user=john",
			expected: "[REDACTED]",
		},
		{
			name:     "query with secret",
			query:    "secret=mysecret&value=test",
			expected: "[REDACTED]",
		},
		{
			name:     "empty query",
			query:    "",
			expected: "",
		},
		{
			name:     "case insensitive matching",
			query:    "PASSWORD=secret123",
			expected: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeQueryParams(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}