package tracing

import (
	"context"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	// httpErrorThreshold is the HTTP status code threshold for errors.
	httpErrorThreshold = 400
)

// GinMiddleware creates a Gin middleware for OpenTelemetry tracing.
func (t *Tracer) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !t.config.Enabled {
			c.Next()
			return
		}

		ctx := t.setupTraceContext(c)
		ctx, span := t.startHTTPSpan(ctx, c)
		defer span.End()

		t.addTraceInfoToContext(c, ctx)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		t.recordResponseInfo(span, c)
		t.recordErrors(span, c)
	}
}

func (t *Tracer) setupTraceContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	return t.ExtractTraceContext(ctx, headers)
}

func (t *Tracer) startHTTPSpan(ctx context.Context, c *gin.Context) (context.Context, trace.Span) {
	spanName := c.Request.Method + " " + c.FullPath()
	if c.FullPath() == "" {
		spanName = c.Request.Method + " " + c.Request.URL.Path
	}

	return t.tracer.Start(ctx,
		spanName,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPMethod(c.Request.Method),
			semconv.HTTPRoute(c.FullPath()),
			semconv.HTTPScheme(c.Request.URL.Scheme),
			attribute.String("http.host", c.Request.Host),
			semconv.HTTPTarget(c.Request.URL.Path),
			attribute.String("http.user_agent", c.Request.UserAgent()),
			attribute.String("http.client_ip", c.ClientIP()),
		),
	)
}

func (t *Tracer) addTraceInfoToContext(c *gin.Context, ctx context.Context) {
	c.Set("trace_id", t.GetTraceID(ctx))
	c.Set("span_id", t.GetSpanID(ctx))
}

func (t *Tracer) recordResponseInfo(span trace.Span, c *gin.Context) {
	status := c.Writer.Status()
	span.SetAttributes(
		semconv.HTTPStatusCode(status),
		attribute.Int64("http.response.size", int64(c.Writer.Size())),
	)

	if status >= httpErrorThreshold {
		span.SetStatus(codes.Error, "HTTP "+strconv.Itoa(status))
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

func (t *Tracer) recordErrors(span trace.Span, c *gin.Context) {
	if len(c.Errors) > 0 {
		for _, err := range c.Errors {
			span.RecordError(err.Err)
		}
	}
}

// GetTraceFromGinContext extracts trace information from Gin context.
func GetTraceFromGinContext(c *gin.Context) (traceID, spanID string) {
	tid, exists := c.Get("trace_id")
	if !exists {
		return "", ""
	}

	traceID, ok := tid.(string)
	if !ok {
		return "", ""
	}

	sid, exists := c.Get("span_id")
	if !exists {
		return traceID, ""
	}

	spanID, ok = sid.(string)
	if !ok {
		return traceID, ""
	}

	return traceID, spanID
}

// StartSpanFromGinContext starts a new span from Gin context.
func (t *Tracer) StartSpanFromGinContext(
	c *gin.Context, name string, opts ...trace.SpanStartOption,
) (context.Context, trace.Span) {
	ctx := c.Request.Context()
	return t.tracer.Start(ctx, name, opts...)
}

// AddTraceHeadersToResponse adds trace headers to the HTTP response.
func (t *Tracer) AddTraceHeadersToResponse(c *gin.Context) {
	if traceID, spanID := GetTraceFromGinContext(c); traceID != "" {
		c.Header("X-Trace-ID", traceID)
		c.Header("X-Span-ID", spanID)
	}
}

// TracingContextMiddleware adds tracing context to Gin context for easier access.
func (t *Tracer) TracingContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add tracer to context for easy access in handlers
		c.Set("tracer", t)
		c.Next()
	}
}

// GetTracerFromGinContext extracts the tracer from Gin context.
func GetTracerFromGinContext(c *gin.Context) *Tracer {
	if tracer, exists := c.Get("tracer"); exists {
		if t, ok := tracer.(*Tracer); ok {
			return t
		}
	}
	return nil
}

// TraceGinHandler wraps a Gin handler with automatic tracing.
func (t *Tracer) TraceGinHandler(name string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !t.config.Enabled {
			handler(c)
			return
		}

		ctx, span := t.StartSpanFromGinContext(c, name)
		defer span.End()

		// Replace request context
		c.Request = c.Request.WithContext(ctx)

		// Call the original handler
		handler(c)

		// Record any errors that occurred
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				t.RecordError(span, err.Err)
			}
		}
	}
}

// InstrumentHTTPClient creates an instrumented HTTP client for external requests.
func (t *Tracer) InstrumentHTTPClient() *HTTPClientInstrumentation {
	return &HTTPClientInstrumentation{
		tracer: t,
	}
}

// HTTPClientInstrumentation provides tracing for HTTP client requests.
type HTTPClientInstrumentation struct {
	tracer *Tracer
}

// InjectHeaders injects tracing headers into an HTTP request.
func (h *HTTPClientInstrumentation) InjectHeaders(ctx context.Context, headers map[string]string) {
	h.tracer.InjectTraceContext(ctx, headers)
}

// StartClientSpan starts a span for an outgoing HTTP request.
func (h *HTTPClientInstrumentation) StartClientSpan(
	ctx context.Context, method, url string,
) (context.Context, trace.Span) {
	spanName := method + " " + url
	return h.tracer.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPMethod(method),
			semconv.HTTPURL(url),
		),
	)
}
