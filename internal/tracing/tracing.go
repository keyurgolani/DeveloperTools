package tracing

import (
	"context"
	"fmt"

	"dev-utilities/internal/version"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds tracing configuration
type Config struct {
	Enabled     bool   `json:"enabled"`
	ServiceName string `json:"serviceName"`
	Environment string `json:"environment"`
	Exporter    string `json:"exporter"` // "jaeger", "otlp", or "noop"
	
	// Jaeger configuration
	JaegerEndpoint string `json:"jaegerEndpoint"`
	
	// OTLP configuration
	OTLPEndpoint string `json:"otlpEndpoint"`
	OTLPHeaders  map[string]string `json:"otlpHeaders"`
	
	// Sampling configuration
	SampleRate float64 `json:"sampleRate"` // 0.0 to 1.0
}

// Tracer wraps OpenTelemetry tracer with application-specific functionality
type Tracer struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	config   *Config
}

// New creates a new tracer instance
func New(config *Config) (*Tracer, error) {
	if !config.Enabled {
		// Return a no-op tracer
		return &Tracer{
			tracer: otel.Tracer("dev-utilities"),
			config: config,
		}, nil
	}

	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(version.Version),
			semconv.DeploymentEnvironment(config.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on configuration
	var exporter sdktrace.SpanExporter
	switch config.Exporter {
	case "jaeger":
		exporter, err = createJaegerExporter(config)
	case "otlp":
		exporter, err = createOTLPExporter(config)
	case "noop":
		// Use no-op exporter for testing
		exporter = &noopExporter{}
	default:
		return nil, fmt.Errorf("unsupported exporter: %s", config.Exporter)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create sampler
	sampler := sdktrace.AlwaysSample()
	if config.SampleRate > 0 && config.SampleRate < 1.0 {
		sampler = sdktrace.TraceIDRatioBased(config.SampleRate)
	}

	// Create trace provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider and propagator
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := provider.Tracer("dev-utilities")

	return &Tracer{
		tracer:   tracer,
		provider: provider,
		config:   config,
	}, nil
}

// createJaegerExporter creates a Jaeger exporter
func createJaegerExporter(config *Config) (sdktrace.SpanExporter, error) {
	endpoint := config.JaegerEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:14268/api/traces"
	}

	return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
}

// createOTLPExporter creates an OTLP HTTP exporter
func createOTLPExporter(config *Config) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{}
	
	if config.OTLPEndpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(config.OTLPEndpoint))
	}
	
	if len(config.OTLPHeaders) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(config.OTLPHeaders))
	}

	return otlptracehttp.New(context.Background(), opts...)
}

// StartSpan starts a new span with the given name and options
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// StartHTTPSpan starts a span for HTTP operations
func (t *Tracer) StartHTTPSpan(ctx context.Context, method, path string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("%s %s", method, path)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPMethod(method),
			semconv.HTTPRoute(path),
		),
	)
	return ctx, span
}

// StartCryptoSpan starts a span for cryptographic operations
func (t *Tracer) StartCryptoSpan(ctx context.Context, operation, algorithm string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("crypto.%s", operation)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("crypto.operation", operation),
			attribute.String("crypto.algorithm", algorithm),
		),
	)
	return ctx, span
}

// StartTextSpan starts a span for text processing operations
func (t *Tracer) StartTextSpan(ctx context.Context, operation string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("text.%s", operation)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("text.operation", operation),
		),
	)
	return ctx, span
}

// StartTransformSpan starts a span for data transformation operations
func (t *Tracer) StartTransformSpan(ctx context.Context, operation, format string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("transform.%s", operation)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("transform.operation", operation),
			attribute.String("transform.format", format),
		),
	)
	return ctx, span
}

// StartNetworkSpan starts a span for network operations
func (t *Tracer) StartNetworkSpan(ctx context.Context, operation string, target string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("network.%s", operation)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("network.operation", operation),
			attribute.String("network.target", target),
		),
	)
	return ctx, span
}

// RecordError records an error in the current span
func (t *Tracer) RecordError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// SetSpanAttributes sets attributes on a span
func (t *Tracer) SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// Shutdown gracefully shuts down the tracer
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t.provider != nil {
		return t.provider.Shutdown(ctx)
	}
	return nil
}

// GetTraceID returns the trace ID from the current span context
func (t *Tracer) GetTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// GetSpanID returns the span ID from the current span context
func (t *Tracer) GetSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// InjectTraceContext injects trace context into headers
func (t *Tracer) InjectTraceContext(ctx context.Context, headers map[string]string) {
	otel.GetTextMapPropagator().Inject(ctx, &mapCarrier{headers})
}

// ExtractTraceContext extracts trace context from headers
func (t *Tracer) ExtractTraceContext(ctx context.Context, headers map[string]string) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, &mapCarrier{headers})
}

// mapCarrier implements TextMapCarrier for map[string]string
type mapCarrier struct {
	data map[string]string
}

func (c *mapCarrier) Get(key string) string {
	return c.data[key]
}

func (c *mapCarrier) Set(key, value string) {
	c.data[key] = value
}

func (c *mapCarrier) Keys() []string {
	keys := make([]string, 0, len(c.data))
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

// noopExporter is a no-op exporter for testing
type noopExporter struct{}

func (e *noopExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return nil
}

func (e *noopExporter) Shutdown(ctx context.Context) error {
	return nil
}

// Helper functions for common tracing patterns

// TraceFunction wraps a function with tracing
func (t *Tracer) TraceFunction(ctx context.Context, name string, fn func(context.Context) error) error {
	ctx, span := t.tracer.Start(ctx, name)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		t.RecordError(span, err)
	}

	return err
}

// TraceFunctionWithResult wraps a function with tracing and returns a result
// Note: Generic version removed for compatibility - use TraceFunctionWithInterface instead
func (t *Tracer) TraceFunctionWithInterface(ctx context.Context, name string, fn func(context.Context) (interface{}, error)) (interface{}, error) {
	ctx, span := t.tracer.Start(ctx, name)
	defer span.End()

	result, err := fn(ctx)
	if err != nil {
		t.RecordError(span, err)
	}

	return result, err
}

// AddSpanEvent adds an event to the current span
func (t *Tracer) AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetSpanStatus sets the status of the current span
func (t *Tracer) SetSpanStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	span.SetStatus(code, description)
}

// DefaultConfig returns a default tracing configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     false,
		ServiceName: "dev-utilities",
		Environment: "development",
		Exporter:    "noop",
		SampleRate:  1.0,
	}
}