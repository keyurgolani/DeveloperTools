package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the application
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

// New creates a new Metrics instance with all Prometheus metrics registered
func New() *Metrics {
	return NewWithRegistry(prometheus.DefaultRegisterer)
}

// NewWithRegistry creates a new Metrics instance with a custom registry (useful for testing)
func NewWithRegistry(registerer prometheus.Registerer) *Metrics {
	factory := promauto.With(registerer)
	
	// Convert registerer to gatherer if possible
	var gatherer prometheus.Gatherer
	if reg, ok := registerer.(*prometheus.Registry); ok {
		gatherer = reg
	} else {
		gatherer = prometheus.DefaultGatherer
	}
	
	m := &Metrics{
		// Registry
		registry: gatherer,
		
		// HTTP metrics
		httpRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status_code"},
		),
		httpRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		httpRequestSize: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_size_bytes",
				Help:    "HTTP request size in bytes",
				Buckets: []float64{100, 1000, 10000, 100000, 1000000},
			},
			[]string{"method", "path"},
		),
		httpResponseSize: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "HTTP response size in bytes",
				Buckets: []float64{100, 1000, 10000, 100000, 1000000},
			},
			[]string{"method", "path"},
		),

		// Business metrics
		cryptoOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "crypto_operations_total",
				Help: "Total number of cryptographic operations",
			},
			[]string{"operation", "algorithm", "status"},
		),
		textOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "text_operations_total",
				Help: "Total number of text processing operations",
			},
			[]string{"operation", "status"},
		),
		transformOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "transform_operations_total",
				Help: "Total number of data transformation operations",
			},
			[]string{"operation", "format", "status"},
		),
		idOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "id_operations_total",
				Help: "Total number of ID generation operations",
			},
			[]string{"operation", "type", "status"},
		),
		timeOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "time_operations_total",
				Help: "Total number of time utility operations",
			},
			[]string{"operation", "status"},
		),
		networkOperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "network_operations_total",
				Help: "Total number of network utility operations",
			},
			[]string{"operation", "status"},
		),

		// Error metrics
		errorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "errors_total",
				Help: "Total number of errors by type",
			},
			[]string{"type", "module"},
		),

		// Rate limiting metrics
		rateLimitHitsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rate_limit_hits_total",
				Help: "Total number of rate limit hits",
			},
			[]string{"client_type", "operation"},
		),

		// System metrics
		activeConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "active_connections",
				Help: "Number of active connections",
			},
		),
	}

	return m
}

// RecordHTTPRequest records metrics for an HTTP request
func (m *Metrics) RecordHTTPRequest(method, path string, statusCode int, duration time.Duration, requestSize, responseSize int64) {
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

// RecordCryptoOperation records metrics for cryptographic operations
func (m *Metrics) RecordCryptoOperation(operation, algorithm, status string) {
	m.cryptoOperationsTotal.WithLabelValues(operation, algorithm, status).Inc()
}

// RecordTextOperation records metrics for text processing operations
func (m *Metrics) RecordTextOperation(operation, status string) {
	m.textOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordTransformOperation records metrics for data transformation operations
func (m *Metrics) RecordTransformOperation(operation, format, status string) {
	m.transformOperationsTotal.WithLabelValues(operation, format, status).Inc()
}

// RecordIDOperation records metrics for ID generation operations
func (m *Metrics) RecordIDOperation(operation, idType, status string) {
	m.idOperationsTotal.WithLabelValues(operation, idType, status).Inc()
}

// RecordTimeOperation records metrics for time utility operations
func (m *Metrics) RecordTimeOperation(operation, status string) {
	m.timeOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordNetworkOperation records metrics for network utility operations
func (m *Metrics) RecordNetworkOperation(operation, status string) {
	m.networkOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordError records error metrics
func (m *Metrics) RecordError(errorType, module string) {
	m.errorsTotal.WithLabelValues(errorType, module).Inc()
}

// RecordRateLimitHit records rate limiting metrics
func (m *Metrics) RecordRateLimitHit(clientType, operation string) {
	m.rateLimitHitsTotal.WithLabelValues(clientType, operation).Inc()
}

// SetActiveConnections sets the number of active connections
func (m *Metrics) SetActiveConnections(count float64) {
	m.activeConnections.Set(count)
}

// Handler returns the Prometheus metrics HTTP handler
func (m *Metrics) Handler() gin.HandlerFunc {
	h := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	return gin.WrapH(h)
}

// MetricsMiddleware creates a Gin middleware for collecting HTTP metrics
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