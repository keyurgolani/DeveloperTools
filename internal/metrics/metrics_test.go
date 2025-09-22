package metrics_test

import (
	"context"
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

func TestNew(t *testing.T) {
	// Test the default New() function
	metricsInstance := metrics.New()
	assert.NotNil(t, metricsInstance)
	assert.NotNil(t, metricsInstance.HTTPRequestsTotal())
	assert.NotNil(t, metricsInstance.CryptoOperationsTotal())
	assert.NotNil(t, metricsInstance.TextOperationsTotal())
	assert.NotNil(t, metricsInstance.TransformOperationsTotal())
	assert.NotNil(t, metricsInstance.IDOperationsTotal())
	assert.NotNil(t, metricsInstance.TimeOperationsTotal())
	assert.NotNil(t, metricsInstance.NetworkOperationsTotal())
	assert.NotNil(t, metricsInstance.ErrorsTotal())
}

func TestNewWithRegistry(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)
	assert.NotNil(t, metricsInstance)
	assert.NotNil(t, metricsInstance.HTTPRequestsTotal())
	assert.NotNil(t, metricsInstance.CryptoOperationsTotal())
	assert.NotNil(t, metricsInstance.TextOperationsTotal())
	assert.NotNil(t, metricsInstance.TransformOperationsTotal())
	assert.NotNil(t, metricsInstance.IDOperationsTotal())
	assert.NotNil(t, metricsInstance.TimeOperationsTotal())
	assert.NotNil(t, metricsInstance.NetworkOperationsTotal())
	assert.NotNil(t, metricsInstance.ErrorsTotal())
}

func TestRecordHTTPRequest(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a test HTTP request
	metricsInstance.RecordHTTPRequest("GET", "/test", 200, 100*time.Millisecond, 1024, 2048)

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.HTTPRequestsTotal().WithLabelValues("GET", "/test", "200"))
	assert.Equal(t, float64(1), counter)

	// Verify histogram was recorded by checking if it exists (we can't easily check count without more complex setup)
	// For now, just verify the histogram metric exists by checking it doesn't panic
	assert.NotNil(t, metricsInstance.HTTPRequestsTotal())
}

func TestRecordCryptoOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a crypto operation
	metricsInstance.RecordCryptoOperation("hash", "sha256", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hash", "sha256", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTextOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a text operation
	metricsInstance.RecordTextOperation("case_convert", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.TextOperationsTotal().WithLabelValues("case_convert", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTransformOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a transform operation
	metricsInstance.RecordTransformOperation("encode", "base64", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.TransformOperationsTotal().WithLabelValues("encode", "base64", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordIDOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record an ID operation
	metricsInstance.RecordIDOperation("generate", "uuid", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.IDOperationsTotal().WithLabelValues("generate", "uuid", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTimeOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a time operation
	metricsInstance.RecordTimeOperation("convert", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.TimeOperationsTotal().WithLabelValues("convert", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordNetworkOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a network operation
	metricsInstance.RecordNetworkOperation("dns_lookup", "success")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.NetworkOperationsTotal().WithLabelValues("dns_lookup", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordError(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record an error
	metricsInstance.RecordError("validation_error", "crypto")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("validation_error", "crypto"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordRateLimitHit(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record a rate limit hit
	metricsInstance.RecordRateLimitHit("anonymous", "crypto")

	// Verify the counter was incremented
	counter := testutil.ToFloat64(metricsInstance.RateLimitHitsTotal().WithLabelValues("anonymous", "crypto"))
	assert.Equal(t, float64(1), counter)
}

func TestSetActiveConnections(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Set active connections
	metricsInstance.SetActiveConnections(42)

	// Verify the gauge was set
	value := testutil.ToFloat64(metricsInstance.ActiveConnections())
	assert.Equal(t, float64(42), value)
}

func TestHandler(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Get the handler
	handler := metricsInstance.Handler()
	assert.NotNil(t, handler)

	// Test the handler with a request
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", handler)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/metrics", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "# HELP")
	assert.Contains(t, w.Body.String(), "# TYPE")
}

func TestMetricsMiddleware(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Set up test router with metrics middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metricsInstance.MetricsMiddleware())

	// Add test endpoints
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	router.GET("/error", func(c *gin.Context) {
		c.JSON(400, gin.H{"error": "bad request"})
	})

	router.GET("/server-error", func(c *gin.Context) {
		c.JSON(500, gin.H{"error": "internal error"})
	})

	// Test successful request
	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify metrics were recorded
	counter := testutil.ToFloat64(metricsInstance.HTTPRequestsTotal().WithLabelValues("GET", "/test", "200"))
	assert.Equal(t, float64(1), counter)

	// Test client error
	req, err = http.NewRequestWithContext(context.Background(), "GET", "/error", nil)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Verify error metrics were recorded
	errorCounter := testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("client_error", "http"))
	assert.Equal(t, float64(1), errorCounter)

	// Test server error
	req, err = http.NewRequestWithContext(context.Background(), "GET", "/server-error", nil)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Verify server error metrics were recorded
	serverErrorCounter := testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("server_error", "http"))
	assert.Equal(t, float64(1), serverErrorCounter)
}

func TestMetricsIntegration(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()

	metricsInstance := metrics.NewWithRegistry(registry)

	// Record various operations
	metricsInstance.RecordCryptoOperation("hash", "sha256", "success")
	metricsInstance.RecordCryptoOperation("hash", "sha256", "success") // Record twice to test counter
	metricsInstance.RecordCryptoOperation("hash", "md5", "success")
	metricsInstance.RecordCryptoOperation("hmac", "sha256", "error")

	metricsInstance.RecordTextOperation("case_convert", "success")
	metricsInstance.RecordTextOperation("analyze", "success")

	metricsInstance.RecordTransformOperation("encode", "base64", "success")
	metricsInstance.RecordTransformOperation("decode", "jwt", "error")

	metricsInstance.RecordIDOperation("generate", "uuid", "success")
	metricsInstance.RecordTimeOperation("convert", "success")
	metricsInstance.RecordNetworkOperation("dns_lookup", "success")

	metricsInstance.RecordError("validation_error", "crypto")
	metricsInstance.RecordRateLimitHit("anonymous", "crypto")
	metricsInstance.SetActiveConnections(10)

	// Verify all metrics were recorded correctly
	assert.Equal(t, float64(2), testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hash", "sha256", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hash", "md5", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.CryptoOperationsTotal().WithLabelValues("hmac", "sha256", "error")))

	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.TextOperationsTotal().WithLabelValues("case_convert", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.TextOperationsTotal().WithLabelValues("analyze", "success")))

	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.TransformOperationsTotal().WithLabelValues("encode", "base64", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.TransformOperationsTotal().WithLabelValues("decode", "jwt", "error")))

	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.IDOperationsTotal().WithLabelValues("generate", "uuid", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.TimeOperationsTotal().WithLabelValues("convert", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.NetworkOperationsTotal().WithLabelValues("dns_lookup", "success")))

	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.ErrorsTotal().WithLabelValues("validation_error", "crypto")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metricsInstance.RateLimitHitsTotal().WithLabelValues("anonymous", "crypto")))
	assert.Equal(t, float64(10), testutil.ToFloat64(metricsInstance.ActiveConnections()))
}

// Benchmark tests
func BenchmarkRecordHTTPRequest(b *testing.B) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metricsInstance.RecordHTTPRequest("GET", "/test", 200, 100*time.Millisecond, 1024, 2048)
	}
}

func BenchmarkRecordCryptoOperation(b *testing.B) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metricsInstance.RecordCryptoOperation("hash", "sha256", "success")
	}
}

func BenchmarkMetricsMiddleware(b *testing.B) {
	registry := prometheus.NewRegistry()
	metricsInstance := metrics.NewWithRegistry(registry)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metricsInstance.MetricsMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
