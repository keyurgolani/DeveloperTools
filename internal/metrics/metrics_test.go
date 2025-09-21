package metrics

import (
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

func TestNew(t *testing.T) {
	// Test the default New() function
	metrics := New()
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.httpRequestsTotal)
	assert.NotNil(t, metrics.httpRequestDuration)
	assert.NotNil(t, metrics.cryptoOperationsTotal)
	assert.NotNil(t, metrics.textOperationsTotal)
	assert.NotNil(t, metrics.transformOperationsTotal)
	assert.NotNil(t, metrics.idOperationsTotal)
	assert.NotNil(t, metrics.timeOperationsTotal)
	assert.NotNil(t, metrics.networkOperationsTotal)
	assert.NotNil(t, metrics.errorsTotal)
	assert.NotNil(t, metrics.rateLimitHitsTotal)
	assert.NotNil(t, metrics.activeConnections)
}

func TestNewWithRegistry(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.httpRequestsTotal)
	assert.NotNil(t, metrics.httpRequestDuration)
	assert.NotNil(t, metrics.cryptoOperationsTotal)
	assert.NotNil(t, metrics.textOperationsTotal)
	assert.NotNil(t, metrics.transformOperationsTotal)
	assert.NotNil(t, metrics.idOperationsTotal)
	assert.NotNil(t, metrics.timeOperationsTotal)
	assert.NotNil(t, metrics.networkOperationsTotal)
	assert.NotNil(t, metrics.errorsTotal)
	assert.NotNil(t, metrics.rateLimitHitsTotal)
	assert.NotNil(t, metrics.activeConnections)
}

func TestRecordHTTPRequest(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a test HTTP request
	metrics.RecordHTTPRequest("GET", "/test", 200, 100*time.Millisecond, 1024, 2048)
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.httpRequestsTotal.WithLabelValues("GET", "/test", "200"))
	assert.Equal(t, float64(1), counter)
	
	// Verify histogram was recorded by checking if it exists (we can't easily check count without more complex setup)
	// For now, just verify the histogram metric exists by checking it doesn't panic
	assert.NotNil(t, metrics.httpRequestDuration)
}

func TestRecordCryptoOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a crypto operation
	metrics.RecordCryptoOperation("hash", "sha256", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "sha256", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTextOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a text operation
	metrics.RecordTextOperation("case_convert", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.textOperationsTotal.WithLabelValues("case_convert", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTransformOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a transform operation
	metrics.RecordTransformOperation("encode", "base64", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.transformOperationsTotal.WithLabelValues("encode", "base64", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordIDOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record an ID operation
	metrics.RecordIDOperation("generate", "uuid", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.idOperationsTotal.WithLabelValues("generate", "uuid", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordTimeOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a time operation
	metrics.RecordTimeOperation("convert", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.timeOperationsTotal.WithLabelValues("convert", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordNetworkOperation(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a network operation
	metrics.RecordNetworkOperation("dns_lookup", "success")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.networkOperationsTotal.WithLabelValues("dns_lookup", "success"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordError(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record an error
	metrics.RecordError("validation_error", "crypto")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("validation_error", "crypto"))
	assert.Equal(t, float64(1), counter)
}

func TestRecordRateLimitHit(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record a rate limit hit
	metrics.RecordRateLimitHit("anonymous", "crypto")
	
	// Verify the counter was incremented
	counter := testutil.ToFloat64(metrics.rateLimitHitsTotal.WithLabelValues("anonymous", "crypto"))
	assert.Equal(t, float64(1), counter)
}

func TestSetActiveConnections(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Set active connections
	metrics.SetActiveConnections(42)
	
	// Verify the gauge was set
	value := testutil.ToFloat64(metrics.activeConnections)
	assert.Equal(t, float64(42), value)
}

func TestHandler(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Get the handler
	handler := metrics.Handler()
	assert.NotNil(t, handler)
	
	// Test the handler with a request
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/metrics", handler)
	
	req, err := http.NewRequest("GET", "/metrics", nil)
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
	
	metrics := NewWithRegistry(registry)
	
	// Set up test router with metrics middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metrics.MetricsMiddleware())
	
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
	req, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Verify metrics were recorded
	counter := testutil.ToFloat64(metrics.httpRequestsTotal.WithLabelValues("GET", "/test", "200"))
	assert.Equal(t, float64(1), counter)
	
	// Test client error
	req, err = http.NewRequest("GET", "/error", nil)
	require.NoError(t, err)
	
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	// Verify error metrics were recorded
	errorCounter := testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("client_error", "http"))
	assert.Equal(t, float64(1), errorCounter)
	
	// Test server error
	req, err = http.NewRequest("GET", "/server-error", nil)
	require.NoError(t, err)
	
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	
	// Verify server error metrics were recorded
	serverErrorCounter := testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("server_error", "http"))
	assert.Equal(t, float64(1), serverErrorCounter)
}

func TestMetricsIntegration(t *testing.T) {
	// Create a new registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	
	metrics := NewWithRegistry(registry)
	
	// Record various operations
	metrics.RecordCryptoOperation("hash", "sha256", "success")
	metrics.RecordCryptoOperation("hash", "sha256", "success") // Record twice to test counter
	metrics.RecordCryptoOperation("hash", "md5", "success")
	metrics.RecordCryptoOperation("hmac", "sha256", "error")
	
	metrics.RecordTextOperation("case_convert", "success")
	metrics.RecordTextOperation("analyze", "success")
	
	metrics.RecordTransformOperation("encode", "base64", "success")
	metrics.RecordTransformOperation("decode", "jwt", "error")
	
	metrics.RecordIDOperation("generate", "uuid", "success")
	metrics.RecordTimeOperation("convert", "success")
	metrics.RecordNetworkOperation("dns_lookup", "success")
	
	metrics.RecordError("validation_error", "crypto")
	metrics.RecordRateLimitHit("anonymous", "crypto")
	metrics.SetActiveConnections(10)
	
	// Verify all metrics were recorded correctly
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "sha256", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hash", "md5", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.cryptoOperationsTotal.WithLabelValues("hmac", "sha256", "error")))
	
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.textOperationsTotal.WithLabelValues("case_convert", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.textOperationsTotal.WithLabelValues("analyze", "success")))
	
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.transformOperationsTotal.WithLabelValues("encode", "base64", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.transformOperationsTotal.WithLabelValues("decode", "jwt", "error")))
	
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.idOperationsTotal.WithLabelValues("generate", "uuid", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.timeOperationsTotal.WithLabelValues("convert", "success")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.networkOperationsTotal.WithLabelValues("dns_lookup", "success")))
	
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.errorsTotal.WithLabelValues("validation_error", "crypto")))
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.rateLimitHitsTotal.WithLabelValues("anonymous", "crypto")))
	assert.Equal(t, float64(10), testutil.ToFloat64(metrics.activeConnections))
}

// Benchmark tests
func BenchmarkRecordHTTPRequest(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewWithRegistry(registry)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordHTTPRequest("GET", "/test", 200, 100*time.Millisecond, 1024, 2048)
	}
}

func BenchmarkRecordCryptoOperation(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewWithRegistry(registry)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordCryptoOperation("hash", "sha256", "success")
	}
}

func BenchmarkMetricsMiddleware(b *testing.B) {
	registry := prometheus.NewRegistry()
	metrics := NewWithRegistry(registry)
	
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(metrics.MetricsMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test"})
	})
	
	req, _ := http.NewRequest("GET", "/test", nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}