package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/version"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_HealthEndpoints(t *testing.T) {
	server := setupTestServer()
	tests := getHealthEndpointTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeHealthEndpointTest(t, server, tt)
		})
	}
}

func setupTestServer() *Server {
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
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	return NewWithMetrics(cfg, logger, metricsInstance)
}

func getHealthEndpointTestCases() []struct {
	name           string
	endpoint       string
	expectedStatus int
	expectedFields []string
} {
	return []struct {
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
}

func executeHealthEndpointTest(t *testing.T, server *Server, tt struct {
	name           string
	endpoint       string
	expectedStatus int
	expectedFields []string
}) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", tt.endpoint, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, req)

	assert.Equal(t, tt.expectedStatus, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	for _, field := range tt.expectedFields {
		assert.Contains(t, response, field, "Response should contain field: %s", field)
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
	srv := NewWithMetrics(cfg, logger, metricsInstance)

	// Create request
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/status", nil)
	require.NoError(t, err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Serve the request
	srv.GetRouter().ServeHTTP(rr, req)

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
	srv := NewWithMetrics(cfg, logger, metricsInstance)

	assert.NotNil(t, srv)
	// Note: config, logger, and router are private fields, so we can't test them directly
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
	srv := NewWithMetrics(cfg, logger, metricsInstance)

	router := srv.GetRouter()
	assert.NotNil(t, router)
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
	srv := NewWithMetrics(cfg, logger, metricsInstance)

	// Create a test request
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
	require.NoError(t, err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Test ServeHTTP method
	srv.GetRouter().ServeHTTP(rr, req)

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
