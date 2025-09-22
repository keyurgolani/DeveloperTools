package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestGinMiddleware(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		// Verify trace context is available
		traceID, spanID := GetTraceFromGinContext(c)
		assert.NotEmpty(t, traceID)
		assert.NotEmpty(t, spanID)

		c.JSON(200, gin.H{"message": "success"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinMiddlewareDisabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	tracer, err := New(config)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinMiddlewareWithError(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/error", func(c *gin.Context) {
		_ = c.Error(assert.AnError)
		c.JSON(500, gin.H{"error": "internal error"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/error", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGinMiddlewareWithTraceHeaders(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		tracer.AddTraceHeadersToResponse(c)
		c.JSON(200, gin.H{"message": "success"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Trace-ID"))
	assert.NotEmpty(t, w.Header().Get("X-Span-ID"))
}

func TestTracingContextMiddleware(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.TracingContextMiddleware())

	router.GET("/test", func(c *gin.Context) {
		extractedTracer := GetTracerFromGinContext(c)
		assert.NotNil(t, extractedTracer)
		assert.Equal(t, tracer, extractedTracer)

		c.JSON(200, gin.H{"message": "success"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTraceGinHandler(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	handler := tracer.TraceGinHandler("test-handler", func(c *gin.Context) {
		// Verify we have tracing context
		span := trace.SpanFromContext(c.Request.Context())
		assert.True(t, span.SpanContext().IsValid())

		c.JSON(200, gin.H{"message": "success"})
	})

	router.GET("/test", handler)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTraceGinHandlerDisabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	tracer, err := New(config)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := tracer.TraceGinHandler("test-handler", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	router.GET("/test", handler)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPClientInstrumentation(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	instrumentation := tracer.InstrumentHTTPClient()
	assert.NotNil(t, instrumentation)

	ctx := context.Background()
	ctx, span := instrumentation.StartClientSpan(ctx, "GET", "http://example.com")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()

	// Test header injection
	headers := make(map[string]string)
	instrumentation.InjectHeaders(ctx, headers)
	assert.NotEmpty(t, headers)
}

func TestGetTraceFromGinContextEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	traceID, spanID := GetTraceFromGinContext(c)
	assert.Empty(t, traceID)
	assert.Empty(t, spanID)
}

func TestGetTracerFromGinContextEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	tracer := GetTracerFromGinContext(c)
	assert.Nil(t, tracer)
}

func TestStartSpanFromGinContext(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(t, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		ctx, span := tracer.StartSpanFromGinContext(c, "child-span")
		assert.NotNil(t, span)
		assert.True(t, span.SpanContext().IsValid())

		// Verify parent-child relationship
		parentSpan := trace.SpanFromContext(c.Request.Context())
		childSpan := trace.SpanFromContext(ctx)

		assert.Equal(t, parentSpan.SpanContext().TraceID(), childSpan.SpanContext().TraceID())
		assert.NotEqual(t, parentSpan.SpanContext().SpanID(), childSpan.SpanContext().SpanID())

		span.End()
		c.JSON(200, gin.H{"message": "success"})
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Benchmark tests.
func BenchmarkGinMiddleware(b *testing.B) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}

	tracer, err := New(config)
	require.NoError(b, err)
	defer func() { _ = tracer.Shutdown(context.Background()) }()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkGinMiddlewareDisabled(b *testing.B) {
	config := &Config{
		Enabled: false,
	}

	tracer, err := New(config)
	require.NoError(b, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(tracer.GinMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
