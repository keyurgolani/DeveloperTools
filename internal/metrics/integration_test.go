package metrics_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetricsIntegrationWithServer tests the complete metrics integration.
func TestMetricsIntegrationWithServer(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)
	router := setupTestRouterWithMetrics(metricsInstance)

	executeMetricsIntegrationTests(t, router)
	verifyMetricsRecording(t, metricsInstance)
	verifyMetricsEndpoint(t, router, metricsInstance)
}

func setupTestRouterWithMetrics(metricsInstance *metrics.Metrics) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metricsInstance.MetricsMiddleware())
	router.GET("/metrics", metricsInstance.Handler())

	setupCryptoEndpoint(router, metricsInstance)
	setupTextEndpoint(router, metricsInstance)
	setupTransformEndpoint(router, metricsInstance)
	setupIDEndpoint(router, metricsInstance)
	setupTimeEndpoint(router, metricsInstance)
	setupNetworkEndpoint(router, metricsInstance)

	return router
}

func setupCryptoEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/crypto/hash", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metricsInstance.RecordCryptoOperation("hash", "unknown", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		algorithm, hasAlgorithm := req["algorithm"].(string)
		_, hasContent := req["content"].(string)

		if !hasAlgorithm || !hasContent {
			metricsInstance.RecordCryptoOperation("hash", "unknown", "validation_error")
			c.JSON(400, gin.H{"error": "missing required fields"})
			return
		}

		metricsInstance.RecordCryptoOperation("hash", algorithm, "success")
		c.JSON(200, gin.H{"success": true, "hash": "abc123"})
	})
}

func setupTextEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/text/case", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metricsInstance.RecordTextOperation("case_convert", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		metricsInstance.RecordTextOperation("case_convert", "success")
		c.JSON(200, gin.H{"success": true, "result": "HELLO"})
	})
}

func setupTransformEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/transform/base64", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			metricsInstance.RecordTransformOperation("encode", "base64", "validation_error")
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		metricsInstance.RecordTransformOperation("encode", "base64", "success")
		c.JSON(200, gin.H{"success": true, "result": "aGVsbG8="})
	})
}

func setupIDEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/id/uuid", func(c *gin.Context) {
		metricsInstance.RecordIDOperation("generate", "uuid", "success")
		c.JSON(200, gin.H{"success": true, "uuid": "123e4567-e89b-12d3-a456-426614174000"})
	})
}

func setupTimeEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/time/convert", func(c *gin.Context) {
		metricsInstance.RecordTimeOperation("convert", "success")
		c.JSON(200, gin.H{"success": true, "result": "2023-01-01T00:00:00Z"})
	})
}

func setupNetworkEndpoint(router *gin.Engine, metricsInstance *metrics.Metrics) {
	router.POST("/api/v1/network/dns", func(c *gin.Context) {
		metricsInstance.RecordNetworkOperation("dns_lookup", "success")
		c.JSON(200, gin.H{"success": true, "records": []string{"1.2.3.4"}})
	})
}

func executeMetricsIntegrationTests(t *testing.T, router *gin.Engine) {
	tests := getMetricsTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeTestRequest(t, router, tt)
		})
	}
}

type metricsTestCase struct {
	name     string
	method   string
	path     string
	body     map[string]interface{}
	expected int
}

func getMetricsTestCases() []metricsTestCase {
	return []metricsTestCase{
		{
			name:     "successful crypto hash",
			method:   "POST",
			path:     "/api/v1/crypto/hash",
			body:     map[string]interface{}{"content": "hello", "algorithm": "sha256"},
			expected: 200,
		},
		{
			name:     "failed crypto hash",
			method:   "POST",
			path:     "/api/v1/crypto/hash",
			body:     map[string]interface{}{"invalid": "data"},
			expected: 400,
		},
		{
			name:     "successful text operation",
			method:   "POST",
			path:     "/api/v1/text/case",
			body:     map[string]interface{}{"content": "hello", "caseType": "UPPERCASE"},
			expected: 200,
		},
		{
			name:     "successful transform operation",
			method:   "POST",
			path:     "/api/v1/transform/base64",
			body:     map[string]interface{}{"content": "hello", "action": "encode"},
			expected: 200,
		},
		{
			name:     "successful id operation",
			method:   "POST",
			path:     "/api/v1/id/uuid",
			body:     map[string]interface{}{"version": 4},
			expected: 200,
		},
		{
			name:     "successful time operation",
			method:   "POST",
			path:     "/api/v1/time/convert",
			body:     map[string]interface{}{"input": "1640995200", "inputFormat": "unix", "outputFormat": "iso8601"},
			expected: 200,
		},
		{
			name:     "successful network operation",
			method:   "POST",
			path:     "/api/v1/network/dns",
			body:     map[string]interface{}{"domain": "example.com", "recordType": "A"},
			expected: 200,
		},
	}
}

func executeTestRequest(t *testing.T, router *gin.Engine, tt metricsTestCase) {
	bodyBytes, err := json.Marshal(tt.body)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), tt.method, tt.path, bytes.NewBuffer(bodyBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expected, w.Code)
}

func verifyMetricsRecording(t *testing.T, metricsInstance *metrics.Metrics) {
	t.Run("verify HTTP metrics", func(t *testing.T) {
		verifyHTTPMetrics(t, metricsInstance)
	})

	t.Run("verify business metrics", func(t *testing.T) {
		verifyBusinessMetrics(t, metricsInstance)
	})

	t.Run("verify error metrics", func(t *testing.T) {
		verifyErrorMetrics(t, metricsInstance)
	})
}

func verifyHTTPMetrics(t *testing.T, metricsInstance *metrics.Metrics) {
	totalRequests := testutil.ToFloat64(metricsInstance.HTTPRequestsTotal().WithLabelValues(
		"POST", "/api/v1/crypto/hash", "200"))
	assert.Equal(t, float64(1), totalRequests)

	failedRequests := testutil.ToFloat64(metricsInstance.HTTPRequestsTotal().WithLabelValues(
		"POST", "/api/v1/crypto/hash", "400"))
	assert.Equal(t, float64(1), failedRequests)
}

func verifyBusinessMetrics(t *testing.T, metricsInstance *metrics.Metrics) {
	// Check crypto operations
	cryptoSuccess := testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues(
		"hash", "sha256", "success"))
	assert.Equal(t, float64(1), cryptoSuccess)

	cryptoError := testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues(
		"hash", "unknown", "validation_error"))
	assert.Equal(t, float64(1), cryptoError)

	// Check text operations
	textSuccess := testutil.ToFloat64(metricsInstance.TextOperationsTotal().WithLabelValues(
		"case_convert", "success"))
	assert.Equal(t, float64(1), textSuccess)

	// Check transform operations
	transformSuccess := testutil.ToFloat64(metricsInstance.TransformOperationsTotal().WithLabelValues(
		"encode", "base64", "success"))
	assert.Equal(t, float64(1), transformSuccess)

	// Check ID operations
	idSuccess := testutil.ToFloat64(metricsInstance.IDOperationsTotal().WithLabelValues("generate", "uuid", "success"))
	assert.Equal(t, float64(1), idSuccess)

	// Check time operations
	timeSuccess := testutil.ToFloat64(metricsInstance.TimeOperationsTotal().WithLabelValues("convert", "success"))
	assert.Equal(t, float64(1), timeSuccess)

	// Check network operations
	networkSuccess := testutil.ToFloat64(metricsInstance.NetworkOperationsTotal().WithLabelValues("dns_lookup", "success"))
	assert.Equal(t, float64(1), networkSuccess)
}

func verifyErrorMetrics(t *testing.T, metricsInstance *metrics.Metrics) {
	clientErrors := testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("client_error", "http"))
	assert.Greater(t, clientErrors, float64(0))
}

func verifyMetricsEndpoint(t *testing.T, router *gin.Engine, metricsInstance *metrics.Metrics) {
	t.Run("verify metrics endpoint", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), "GET", "/metrics", nil)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		body := w.Body.String()
		verifyMetricsEndpointContent(t, body, metricsInstance)

		t.Logf("Metrics endpoint response contains expected core metrics")
	})
}

func verifyMetricsEndpointContent(t *testing.T, body string, metricsInstance *metrics.Metrics) {
	assert.Contains(t, body, "http_requests_total")
	assert.Contains(t, body, "http_request_duration_seconds")

	// Only check for business metrics if they have been recorded
	if testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hash", "sha256", "success")) > 0 {
		assert.Contains(t, body, "crypto_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.TextOperationsTotal().WithLabelValues("case_convert", "success")) > 0 {
		assert.Contains(t, body, "text_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.TransformOperationsTotal().WithLabelValues("encode", "base64", "success")) > 0 {
		assert.Contains(t, body, "transform_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.IDOperationsTotal().WithLabelValues("generate", "uuid", "success")) > 0 {
		assert.Contains(t, body, "id_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.TimeOperationsTotal().WithLabelValues("convert", "success")) > 0 {
		assert.Contains(t, body, "time_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.NetworkOperationsTotal().WithLabelValues("dns_lookup", "success")) > 0 {
		assert.Contains(t, body, "network_operations_total")
	}
	if testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("client_error", "http")) > 0 {
		assert.Contains(t, body, "errors_total")
	}
}

// TestMetricsPerformance tests the performance impact of metrics collection.
func TestMetricsPerformance(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metricsInstance.MetricsMiddleware())

	router.GET("/test", func(c *gin.Context) {
		metricsInstance.RecordCryptoOperation("hash", "sha256", "success")
		c.JSON(200, gin.H{"success": true})
	})

	// Warm up
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
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
	counter := testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hash", "sha256", "success"))
	assert.Equal(t, float64(1100), counter) // 100 warmup + 1000 test requests
}

// TestMetricsLabelsValidation tests that metric labels are properly validated.
func TestMetricsLabelsValidation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)

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
				metricsInstance.RecordCryptoOperation(tc.operation, tc.algorithm, tc.status)
			})

			// Verify metric was recorded
			counter := testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues(
				tc.operation, tc.algorithm, tc.status))
			assert.Equal(t, float64(1), counter)
		})
	}
}
