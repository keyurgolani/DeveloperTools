package metrics

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetricsIntegrationWithServer tests the complete metrics integration
func TestMetricsIntegrationWithServer(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Set up test server with metrics
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metrics.MetricsMiddleware())
	
	// Add metrics endpoint
	router.GET("/metrics", metrics.Handler())
	
	// Add test endpoints that simulate different modules
	router.POST("/api/v1/crypto/hash", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metrics.RecordCryptoOperation("hash", "unknown", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		
		// Check for required fields to simulate validation
		algorithm, hasAlgorithm := req["algorithm"].(string)
		_, hasContent := req["content"].(string)
		
		if !hasAlgorithm || !hasContent {
			metrics.RecordCryptoOperation("hash", "unknown", "validation_error")
			c.JSON(400, gin.H{"error": "missing required fields"})
			return
		}
		
		metrics.RecordCryptoOperation("hash", algorithm, "success")
		c.JSON(200, gin.H{"success": true, "hash": "abc123"})
	})
	
	router.POST("/api/v1/text/case", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metrics.RecordTextOperation("case_convert", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		
		metrics.RecordTextOperation("case_convert", "success")
		c.JSON(200, gin.H{"success": true, "result": "HELLO"})
	})
	
	router.POST("/api/v1/transform/base64", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metrics.RecordTransformOperation("encode", "base64", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		
		metrics.RecordTransformOperation("encode", "base64", "success")
		c.JSON(200, gin.H{"success": true, "result": "aGVsbG8="})
	})
	
	router.POST("/api/v1/id/uuid", func(c *gin.Context) {
		metrics.RecordIDOperation("generate", "uuid", "success")
		c.JSON(200, gin.H{"success": true, "uuid": "123e4567-e89b-12d3-a456-426614174000"})
	})
	
	router.POST("/api/v1/time/convert", func(c *gin.Context) {
		metrics.RecordTimeOperation("convert", "success")
		c.JSON(200, gin.H{"success": true, "result": "2023-01-01T00:00:00Z"})
	})
	
	router.POST("/api/v1/network/dns", func(c *gin.Context) {
		metrics.RecordNetworkOperation("dns_lookup", "success")
		c.JSON(200, gin.H{"success": true, "records": []string{"1.2.3.4"}})
	})
	
	// Test various operations
	tests := []struct {
		name     string
		method   string
		path     string
		body     map[string]interface{}
		expected int
	}{
		{
			name:   "successful crypto hash",
			method: "POST",
			path:   "/api/v1/crypto/hash",
			body:   map[string]interface{}{"content": "hello", "algorithm": "sha256"},
			expected: 200,
		},
		{
			name:   "failed crypto hash",
			method: "POST",
			path:   "/api/v1/crypto/hash",
			body:   map[string]interface{}{"invalid": "data"},
			expected: 400,
		},
		{
			name:   "successful text operation",
			method: "POST",
			path:   "/api/v1/text/case",
			body:   map[string]interface{}{"content": "hello", "caseType": "UPPERCASE"},
			expected: 200,
		},
		{
			name:   "successful transform operation",
			method: "POST",
			path:   "/api/v1/transform/base64",
			body:   map[string]interface{}{"content": "hello", "action": "encode"},
			expected: 200,
		},
		{
			name:   "successful id operation",
			method: "POST",
			path:   "/api/v1/id/uuid",
			body:   map[string]interface{}{"version": 4},
			expected: 200,
		},
		{
			name:   "successful time operation",
			method: "POST",
			path:   "/api/v1/time/convert",
			body:   map[string]interface{}{"input": "1640995200", "inputFormat": "unix", "outputFormat": "iso8601"},
			expected: 200,
		},
		{
			name:   "successful network operation",
			method: "POST",
			path:   "/api/v1/network/dns",
			body:   map[string]interface{}{"domain": "example.com", "recordType": "A"},
			expected: 200,
		},
	}
	
	// Execute test requests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)
			
			req, err := http.NewRequest(tt.method, tt.path, bytes.NewBuffer(bodyBytes))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expected, w.Code)
		})
	}
	
	// Verify metrics were recorded
	t.Run("verify HTTP metrics", func(t *testing.T) {
		// Check that HTTP requests were recorded
		totalRequests := testutil.ToFloat64(metrics.httpRequestsTotal.WithLabelValues("POST", "/api/v1/crypto/hash", "200"))
		assert.Equal(t, float64(1), totalRequests)
		
		failedRequests := testutil.ToFloat64(metrics.httpRequestsTotal.WithLabelValues("POST", "/api/v1/crypto/hash", "400"))
		assert.Equal(t, float64(1), failedRequests)
	})
	
	t.Run("verify business metrics", func(t *testing.T) {
		// Check crypto operations
		cryptoSuccess := testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "sha256", "success"))
		assert.Equal(t, float64(1), cryptoSuccess)
		
		cryptoError := testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "unknown", "validation_error"))
		assert.Equal(t, float64(1), cryptoError)
		
		// Check text operations
		textSuccess := testutil.ToFloat64(metrics.textOperationsTotal.WithLabelValues("case_convert", "success"))
		assert.Equal(t, float64(1), textSuccess)
		
		// Check transform operations
		transformSuccess := testutil.ToFloat64(metrics.transformOperationsTotal.WithLabelValues("encode", "base64", "success"))
		assert.Equal(t, float64(1), transformSuccess)
		
		// Check ID operations
		idSuccess := testutil.ToFloat64(metrics.idOperationsTotal.WithLabelValues("generate", "uuid", "success"))
		assert.Equal(t, float64(1), idSuccess)
		
		// Check time operations
		timeSuccess := testutil.ToFloat64(metrics.timeOperationsTotal.WithLabelValues("convert", "success"))
		assert.Equal(t, float64(1), timeSuccess)
		
		// Check network operations
		networkSuccess := testutil.ToFloat64(metrics.networkOperationsTotal.WithLabelValues("dns_lookup", "success"))
		assert.Equal(t, float64(1), networkSuccess)
	})
	
	t.Run("verify error metrics", func(t *testing.T) {
		// Check that error metrics were recorded for HTTP errors
		clientErrors := testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("client_error", "http"))
		assert.Greater(t, clientErrors, float64(0))
	})
	
	t.Run("verify metrics endpoint", func(t *testing.T) {
		// Test the metrics endpoint
		req, err := http.NewRequest("GET", "/metrics", nil)
		require.NoError(t, err)
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		// Verify metrics output contains expected metrics
		body := w.Body.String()
		assert.Contains(t, body, "http_requests_total")
		assert.Contains(t, body, "http_request_duration_seconds")
		
		// Only check for business metrics if they have been recorded
		// (they won't appear in output if they haven't been incremented)
		if testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "sha256", "success")) > 0 {
			assert.Contains(t, body, "crypto_operations_total")
		}
		if testutil.ToFloat64(metrics.textOperationsTotal.WithLabelValues("case_convert", "success")) > 0 {
			assert.Contains(t, body, "text_operations_total")
		}
		if testutil.ToFloat64(metrics.transformOperationsTotal.WithLabelValues("encode", "base64", "success")) > 0 {
			assert.Contains(t, body, "transform_operations_total")
		}
		if testutil.ToFloat64(metrics.idOperationsTotal.WithLabelValues("generate", "uuid", "success")) > 0 {
			assert.Contains(t, body, "id_operations_total")
		}
		if testutil.ToFloat64(metrics.timeOperationsTotal.WithLabelValues("convert", "success")) > 0 {
			assert.Contains(t, body, "time_operations_total")
		}
		if testutil.ToFloat64(metrics.networkOperationsTotal.WithLabelValues("dns_lookup", "success")) > 0 {
			assert.Contains(t, body, "network_operations_total")
		}
		if testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("client_error", "http")) > 0 {
			assert.Contains(t, body, "errors_total")
		}
		
		t.Logf("Metrics endpoint response contains expected core metrics")
	})
}

// TestMetricsPerformance tests the performance impact of metrics collection
func TestMetricsPerformance(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewWithRegistry(registry)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metrics.MetricsMiddleware())
	
	router.GET("/test", func(c *gin.Context) {
		metrics.RecordCryptoOperation("hash", "sha256", "success")
		c.JSON(200, gin.H{"success": true})
	})
	
	// Warm up
	req, _ := http.NewRequest("GET", "/test", nil)
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
	
	// Measure performance
	start := time.Now()
	for i := 0; i < 1000; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
	duration := time.Since(start)
	
	// Should be able to handle 1000 requests with metrics in reasonable time
	assert.Less(t, duration, 1*time.Second, "Metrics collection should not significantly impact performance")
	
	// Verify metrics were collected
	counter := testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "sha256", "success"))
	assert.Equal(t, float64(1100), counter) // 100 warmup + 1000 test requests
}

// TestMetricsLabelsValidation tests that metric labels are properly validated
func TestMetricsLabelsValidation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewWithRegistry(registry)
	
	// Test with various label values
	testCases := []struct {
		operation string
		algorithm string
		status    string
	}{
		{"hash", "sha256", "success"},
		{"hash", "md5", "error"},
		{"hmac", "sha512", "success"},
		{"password_hash", "argon2id", "success"},
		{"cert_decode", "x509", "validation_error"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.operation+"_"+tc.algorithm+"_"+tc.status, func(t *testing.T) {
			// Should not panic with any valid label combination
			assert.NotPanics(t, func() {
				metrics.RecordCryptoOperation(tc.operation, tc.algorithm, tc.status)
			})
			
			// Verify metric was recorded
			counter := testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues(tc.operation, tc.algorithm, tc.status))
			assert.Equal(t, float64(1), counter)
		})
	}
}