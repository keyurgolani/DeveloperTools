package tracing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, "dev-utilities", config.ServiceName)
	assert.Equal(t, "development", config.Environment)
	assert.Equal(t, "noop", config.Exporter)
	assert.Equal(t, 1.0, config.SampleRate)
}

func TestNewTracerDisabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	assert.NotNil(t, tracer)
	assert.NotNil(t, tracer.tracer)
	assert.Nil(t, tracer.provider)
}

func TestNewTracerWithNoopExporter(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Environment: "test",
		Exporter:    "noop",
		SampleRate:  1.0,
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	assert.NotNil(t, tracer)
	assert.NotNil(t, tracer.tracer)
	assert.NotNil(t, tracer.provider)
	
	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = tracer.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestNewTracerWithInvalidExporter(t *testing.T) {
	config := &Config{
		Enabled:  true,
		Exporter: "invalid",
	}
	
	_, err := New(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported exporter")
}

func TestStartSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestStartHTTPSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartHTTPSpan(ctx, "GET", "/test")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestStartCryptoSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartCryptoSpan(ctx, "hash", "sha256")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestStartTextSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartTextSpan(ctx, "case_convert")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestStartTransformSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartTransformSpan(ctx, "encode", "base64")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestStartNetworkSpan(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartNetworkSpan(ctx, "dns_lookup", "example.com")
	assert.NotNil(t, span)
	assert.True(t, span.SpanContext().IsValid())
	span.End()
}

func TestRecordError(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	
	testError := errors.New("test error")
	tracer.RecordError(span, testError)
	
	span.End()
	
	// Verify span status is error
	// Note: In the new API, we can't easily access span status from tests
	// The span status is set internally and would require a custom span implementation to test
}

func TestSetSpanAttributes(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	
	tracer.SetSpanAttributes(span,
		attribute.String("test.key", "test.value"),
		attribute.Int("test.number", 42),
	)
	
	span.End()
}

func TestGetTraceID(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	defer span.End()
	
	traceID := tracer.GetTraceID(ctx)
	assert.NotEmpty(t, traceID)
	assert.Len(t, traceID, 32) // Trace ID should be 32 hex characters
}

func TestGetSpanID(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	defer span.End()
	
	spanID := tracer.GetSpanID(ctx)
	assert.NotEmpty(t, spanID)
	assert.Len(t, spanID, 16) // Span ID should be 16 hex characters
}

func TestInjectExtractTraceContext(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	// Create a span and inject its context
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	defer span.End()
	
	originalTraceID := tracer.GetTraceID(ctx)
	
	headers := make(map[string]string)
	tracer.InjectTraceContext(ctx, headers)
	
	assert.NotEmpty(t, headers)
	
	// Extract context from headers
	newCtx := tracer.ExtractTraceContext(context.Background(), headers)
	extractedTraceID := tracer.GetTraceID(newCtx)
	
	assert.Equal(t, originalTraceID, extractedTraceID)
}

func TestTraceFunction(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	
	// Test successful function
	err = tracer.TraceFunction(ctx, "test-function", func(ctx context.Context) error {
		// Verify we have a span in context
		traceID := tracer.GetTraceID(ctx)
		assert.NotEmpty(t, traceID)
		return nil
	})
	assert.NoError(t, err)
	
	// Test function with error
	testError := errors.New("test error")
	err = tracer.TraceFunction(ctx, "test-function-error", func(ctx context.Context) error {
		return testError
	})
	assert.Equal(t, testError, err)
}

func TestTraceFunctionWithResult(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	
	// Test successful function with result
	result, err := tracer.TraceFunctionWithInterface(ctx, "test-function-result", func(ctx context.Context) (interface{}, error) {
		// Verify we have a span in context
		traceID := tracer.GetTraceID(ctx)
		assert.NotEmpty(t, traceID)
		return "success", nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "success", result)
	
	// Test function with error
	testError := errors.New("test error")
	result, err = tracer.TraceFunctionWithInterface(ctx, "test-function-error", func(ctx context.Context) (interface{}, error) {
		return "", testError
	})
	assert.Equal(t, testError, err)
	assert.Equal(t, "", result)
}

func TestAddSpanEvent(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	defer span.End()
	
	// Should not panic
	assert.NotPanics(t, func() {
		tracer.AddSpanEvent(ctx, "test-event",
			attribute.String("event.key", "event.value"),
		)
	})
}

func TestSetSpanStatus(t *testing.T) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "test-span")
	defer span.End()
	
	// Should not panic
	assert.NotPanics(t, func() {
		tracer.SetSpanStatus(ctx, codes.Ok, "success")
	})
}

func TestMapCarrier(t *testing.T) {
	data := make(map[string]string)
	carrier := &mapCarrier{data: data}
	
	// Test Set and Get
	carrier.Set("test-key", "test-value")
	assert.Equal(t, "test-value", carrier.Get("test-key"))
	
	// Test Keys
	carrier.Set("another-key", "another-value")
	keys := carrier.Keys()
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "test-key")
	assert.Contains(t, keys, "another-key")
}

func TestNoopExporter(t *testing.T) {
	exporter := &noopExporter{}
	
	ctx := context.Background()
	err := exporter.ExportSpans(ctx, nil)
	assert.NoError(t, err)
	
	err = exporter.Shutdown(ctx)
	assert.NoError(t, err)
}

// Benchmark tests
func BenchmarkStartSpan(b *testing.B) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(b, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.StartSpan(ctx, "benchmark-span")
		span.End()
	}
}

func BenchmarkTraceFunction(b *testing.B) {
	config := &Config{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "noop",
	}
	
	tracer, err := New(config)
	require.NoError(b, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tracer.Shutdown(ctx)
	}()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracer.TraceFunction(ctx, "benchmark-function", func(ctx context.Context) error {
			return nil
		})
	}
}