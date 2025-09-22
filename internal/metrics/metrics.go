package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the application.
type Metrics struct {
	// Registry for metrics
	registry prometheus.Gatherer

	// HTTP metrics
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
	httpRequestSize     *prometheus.HistogramVec
	httpResponseSize    *prometheus.HistogramVec

	// Business metrics for each module
	cryptoOperationsTotal    *prometheus.CounterVec
	textOperationsTotal      *prometheus.CounterVec
	transformOperationsTotal *prometheus.CounterVec
	idOperationsTotal        *prometheus.CounterVec
	timeOperationsTotal      *prometheus.CounterVec
	networkOperationsTotal   *prometheus.CounterVec

	// Error metrics
	errorsTotal *prometheus.CounterVec

	// Rate limiting metrics
	rateLimitHitsTotal *prometheus.CounterVec

	// System metrics
	activeConnections prometheus.Gauge
}

// New creates a new Metrics instance with all Prometheus metrics registered.
func New() *Metrics {
	return NewWithRegistry(prometheus.DefaultRegisterer)
}

// NewWithRegistry creates a new Metrics instance with a custom registry (useful for testing).
func NewWithRegistry(registerer prometheus.Registerer) *Metrics {
	factory := promauto.With(registerer)
	gatherer := createGatherer(registerer)

	m := &Metrics{
		registry: gatherer,
	}

	initHTTPMetrics(m, factory)
	initBusinessMetrics(m, factory)
	initSystemMetrics(m, factory)

	return m
}

func createGatherer(registerer prometheus.Registerer) prometheus.Gatherer {
	if reg, ok := registerer.(*prometheus.Registry); ok {
		return reg
	}
	return prometheus.DefaultGatherer
}

func initHTTPMetrics(m *Metrics, factory promauto.Factory) {
	m.httpRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status_code"},
	)
	m.httpRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	m.httpRequestSize = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "path"},
	)
	m.httpResponseSize = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "path"},
	)
}

func initBusinessMetrics(m *Metrics, factory promauto.Factory) {
	m.cryptoOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "crypto_operations_total",
			Help: "Total number of cryptographic operations",
		},
		[]string{"operation", "algorithm", "status"},
	)
	m.textOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "text_operations_total",
			Help: "Total number of text processing operations",
		},
		[]string{"operation", "status"},
	)
	m.transformOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "transform_operations_total",
			Help: "Total number of data transformation operations",
		},
		[]string{"operation", "format", "status"},
	)
	m.idOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "id_operations_total",
			Help: "Total number of ID generation operations",
		},
		[]string{"operation", "type", "status"},
	)
	m.timeOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "time_operations_total",
			Help: "Total number of time utility operations",
		},
		[]string{"operation", "status"},
	)
	m.networkOperationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_operations_total",
			Help: "Total number of network utility operations",
		},
		[]string{"operation", "status"},
	)
}

func initSystemMetrics(m *Metrics, factory promauto.Factory) {
	m.errorsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Total number of errors by type",
		},
		[]string{"type", "module"},
	)
	m.rateLimitHitsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"client_type", "operation"},
	)
	m.activeConnections = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)
}

// RecordHTTPRequest records metrics for an HTTP request.
func (m *Metrics) RecordHTTPRequest(
	method, path string, statusCode int, duration time.Duration, requestSize, responseSize int64,
) {
	statusStr := strconv.Itoa(statusCode)

	m.httpRequestsTotal.WithLabelValues(method, path, statusStr).Inc()
	m.httpRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())

	if requestSize > 0 {
		m.httpRequestSize.WithLabelValues(method, path).Observe(float64(requestSize))
	}
	if responseSize > 0 {
		m.httpResponseSize.WithLabelValues(method, path).Observe(float64(responseSize))
	}
}

// RecordCryptoOperation records metrics for cryptographic operations.
func (m *Metrics) RecordCryptoOperation(operation, algorithm, status string) {
	m.cryptoOperationsTotal.WithLabelValues(operation, algorithm, status).Inc()
}

// RecordTextOperation records metrics for text processing operations.
func (m *Metrics) RecordTextOperation(operation, status string) {
	m.textOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordTransformOperation records metrics for data transformation operations.
func (m *Metrics) RecordTransformOperation(operation, format, status string) {
	m.transformOperationsTotal.WithLabelValues(operation, format, status).Inc()
}

// RecordIDOperation records metrics for ID generation operations.
func (m *Metrics) RecordIDOperation(operation, idType, status string) {
	m.idOperationsTotal.WithLabelValues(operation, idType, status).Inc()
}

// RecordTimeOperation records metrics for time utility operations.
func (m *Metrics) RecordTimeOperation(operation, status string) {
	m.timeOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordNetworkOperation records metrics for network utility operations.
func (m *Metrics) RecordNetworkOperation(operation, status string) {
	m.networkOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordError records error metrics.
func (m *Metrics) RecordError(errorType, module string) {
	m.errorsTotal.WithLabelValues(errorType, module).Inc()
}

// RecordRateLimitHit records rate limiting metrics.
func (m *Metrics) RecordRateLimitHit(clientType, operation string) {
	m.rateLimitHitsTotal.WithLabelValues(clientType, operation).Inc()
}

// SetActiveConnections sets the number of active connections.
func (m *Metrics) SetActiveConnections(count float64) {
	m.activeConnections.Set(count)
}

// Handler returns the Prometheus metrics HTTP handler.
func (m *Metrics) Handler() gin.HandlerFunc {
	h := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	return gin.WrapH(h)
}

// MetricsMiddleware creates a Gin middleware for collecting HTTP metrics.
func (m *Metrics) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Get request size
		requestSize := c.Request.ContentLength

		// Process request
		c.Next()

		// Calculate duration and get response info
		duration := time.Since(start)
		statusCode := c.Writer.Status()
		responseSize := int64(c.Writer.Size())

		// Record metrics
		m.RecordHTTPRequest(method, path, statusCode, duration, requestSize, responseSize)

		// Record errors if status code indicates an error
		if statusCode >= 400 {
			errorType := "client_error"
			if statusCode >= 500 {
				errorType = "server_error"
			}
			m.RecordError(errorType, "http")
		}
	}
}

// Getter methods for testing access to internal metrics

// HTTPRequestsTotal returns the HTTP requests total counter.
func (m *Metrics) HTTPRequestsTotal() *prometheus.CounterVec {
	return m.httpRequestsTotal
}

// CryptoOperationsTotal returns the crypto operations total counter.
func (m *Metrics) CryptoOperationsTotal() *prometheus.CounterVec {
	return m.cryptoOperationsTotal
}

// TextOperationsTotal returns the text operations total counter.
func (m *Metrics) TextOperationsTotal() *prometheus.CounterVec {
	return m.textOperationsTotal
}

// TransformOperationsTotal returns the transform operations total counter.
func (m *Metrics) TransformOperationsTotal() *prometheus.CounterVec {
	return m.transformOperationsTotal
}

// IDOperationsTotal returns the ID operations total counter.
func (m *Metrics) IDOperationsTotal() *prometheus.CounterVec {
	return m.idOperationsTotal
}

// TimeOperationsTotal returns the time operations total counter.
func (m *Metrics) TimeOperationsTotal() *prometheus.CounterVec {
	return m.timeOperationsTotal
}

// NetworkOperationsTotal returns the network operations total counter.
func (m *Metrics) NetworkOperationsTotal() *prometheus.CounterVec {
	return m.networkOperationsTotal
}

// ErrorsTotal returns the errors total counter.
func (m *Metrics) ErrorsTotal() *prometheus.CounterVec {
	return m.errorsTotal
}

// RateLimitHitsTotal returns the rate limit hits total counter.
func (m *Metrics) RateLimitHitsTotal() *prometheus.CounterVec {
	return m.rateLimitHitsTotal
}

// ActiveConnections returns the active connections gauge.
func (m *Metrics) ActiveConnections() prometheus.Gauge {
	return m.activeConnections
}
