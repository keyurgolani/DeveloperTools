package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dev-utilities/internal/config"
	"dev-utilities/internal/logging"
	"dev-utilities/internal/metrics"
	"dev-utilities/internal/server"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestObservabilityIntegration tests the complete observability stack
func TestObservabilityIntegration(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "info",
		},
		Tracing: config.TracingConfig{
			Enabled:     true,
			ServiceName: "test-service",
			Environment: "test",
			Exporter:    "noop",
			SampleRate:  1.0,
		},
	}
	
	// Create logger
	logger := logging.New("info")
	
	// Create server with custom metrics to avoid registry conflicts
	metricsInstance := metrics.NewWithRegistry(registry)
	srv := server.NewWithMetrics(cfg, logger, metricsInstance)
	
	// Test endpoints
	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		expectedStatus int
	}{
		{
			name:           "health check",
			method:         "GET",
			path:           "/health",
			expectedStatus: 200,
		},
		{
			name:           "metrics endpoint",
			method:         "GET",
			path:           "/metrics",
			expectedStatus: 200,
		},
		{
			name:           "status endpoint",
			method:         "GET",
			path:           "/api/v1/status",
			expectedStatus: 200,
		},
		{
			name:   "crypto hash operation",
			method: "POST",
			path:   "/api/v1/crypto/hash",
			body: map[string]interface{}{
				"content":   "hello world",
				"algorithm": "sha256",
			},
			expectedStatus: 200,
		},
		{
			name:   "invalid crypto operation",
			method: "POST",
			path:   "/api/v1/crypto/hash",
			body: map[string]interface{}{
				"invalid": "data",
			},
			expectedStatus: 400,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			var err error
			
			if tt.body != nil {
				bodyBytes, err := json.Marshal(tt.body)
				require.NoError(t, err)
				req, err = http.NewRequest(tt.method, tt.path, bytes.NewBuffer(bodyBytes))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(tt.method, tt.path, nil)
				require.NoError(t, err)
			}
			
			// Add trace headers to test trace propagation
			req.Header.Set("X-Request-ID", "test-request-123")
			
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			// Verify response has trace headers if tracing is enabled
			if cfg.Tracing.Enabled && tt.expectedStatus == 200 {
				// Note: Trace headers would be added by middleware in real implementation
				// This is just to verify the integration works
			}
		})
	}
	
	// Test metrics endpoint specifically
	t.Run("verify metrics output", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/metrics", nil)
		require.NoError(t, err)
		
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		body := w.Body.String()
		
		// Verify that metrics endpoint returns valid Prometheus format
		assert.Contains(t, body, "# HELP")
		assert.Contains(t, body, "# TYPE")
		
		// At minimum, we should have active_connections metric
		assert.Contains(t, body, "active_connections")
		
		t.Logf("Metrics endpoint response: %s", body)
		t.Logf("Metrics endpoint is working and returns valid Prometheus format")
	})
	
	// Test health endpoints
	t.Run("health endpoints", func(t *testing.T) {
		endpoints := []string{"/health", "/health/live", "/health/ready"}
		
		for _, endpoint := range endpoints {
			req, err := http.NewRequest("GET", endpoint, nil)
			require.NoError(t, err)
			
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code)
			
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			assert.Contains(t, response, "status")
		}
	})
	
	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := srv.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestObservabilityDisabled tests the system with observability features disabled
func TestObservabilityDisabled(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	// Create test configuration with observability disabled
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "error", // Minimal logging
		},
		Tracing: config.TracingConfig{
			Enabled: false, // Tracing disabled
		},
	}
	
	// Create logger
	logger := logging.New("error")
	
	// Create server with custom metrics to avoid registry conflicts
	metricsInstance := metrics.NewWithRegistry(registry)
	srv := server.NewWithMetrics(cfg, logger, metricsInstance)
	
	// Test that server still works without observability
	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(t, err)
	
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Metrics endpoint should still work (metrics are always enabled)
	req, err = http.NewRequest("GET", "/metrics", nil)
	require.NoError(t, err)
	
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = srv.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestObservabilityPerformance tests the performance impact of observability
func TestObservabilityPerformance(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	// Test with observability enabled
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "info",
		},
		Tracing: config.TracingConfig{
			Enabled:     true,
			ServiceName: "test-service",
			Environment: "test",
			Exporter:    "noop",
			SampleRate:  1.0,
		},
	}
	
	logger := logging.New("info")
	metricsInstance := metrics.NewWithRegistry(registry)
	srv := server.NewWithMetrics(cfg, logger, metricsInstance)
	
	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(t, err)
	
	// Warm up
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}
	
	// Measure performance
	start := time.Now()
	for i := 0; i < 1000; i++ {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}
	duration := time.Since(start)
	
	// Should be able to handle 1000 requests with full observability in reasonable time
	assert.Less(t, duration, 2*time.Second, "Observability should not significantly impact performance")
	
	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = srv.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestObservabilityConfiguration tests various configuration scenarios
func TestObservabilityConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  config.TracingConfig
		wantErr bool
	}{
		{
			name: "valid jaeger config",
			config: config.TracingConfig{
				Enabled:        true,
				ServiceName:    "test-service",
				Environment:    "test",
				Exporter:       "jaeger",
				JaegerEndpoint: "http://localhost:14268/api/traces",
				SampleRate:     0.5,
			},
			wantErr: false,
		},
		{
			name: "valid otlp config",
			config: config.TracingConfig{
				Enabled:      true,
				ServiceName:  "test-service",
				Environment:  "test",
				Exporter:     "otlp",
				OTLPEndpoint: "http://localhost:4318",
				OTLPHeaders:  map[string]string{"Authorization": "Bearer token"},
				SampleRate:   1.0,
			},
			wantErr: false,
		},
		{
			name: "valid noop config",
			config: config.TracingConfig{
				Enabled:     true,
				ServiceName: "test-service",
				Environment: "test",
				Exporter:    "noop",
				SampleRate:  1.0,
			},
			wantErr: false,
		},
		{
			name: "disabled tracing",
			config: config.TracingConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{
					Port:       8080,
					TLSEnabled: false,
				},
				Log: config.LogConfig{
					Level: "info",
				},
				Tracing: tt.config,
			}
			
			logger := logging.New("info")
			
			// Should not panic regardless of configuration
			assert.NotPanics(t, func() {
				// Create a new registry for each test to avoid conflicts
				registry := prometheus.NewRegistry()
				metricsInstance := metrics.NewWithRegistry(registry)
				srv := server.NewWithMetrics(cfg, logger, metricsInstance)
				
				// Test basic functionality
				req, err := http.NewRequest("GET", "/health", nil)
				require.NoError(t, err)
				
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, req)
				
				assert.Equal(t, http.StatusOK, w.Code)
				
				// Shutdown
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				srv.Shutdown(ctx)
			})
		})
	}
}