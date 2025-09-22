package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/constants"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/internal/middleware"
	"github.com/keyurgolani/DeveloperTools/internal/modules/crypto"
	"github.com/keyurgolani/DeveloperTools/internal/modules/id"
	"github.com/keyurgolani/DeveloperTools/internal/modules/network"
	"github.com/keyurgolani/DeveloperTools/internal/modules/text"
	timeModule "github.com/keyurgolani/DeveloperTools/internal/modules/time"
	"github.com/keyurgolani/DeveloperTools/internal/modules/transform"
	"github.com/keyurgolani/DeveloperTools/internal/tracing"
	"github.com/keyurgolani/DeveloperTools/internal/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Server represents the HTTP server.
type Server struct {
	config     *config.Config
	router     *gin.Engine
	httpServer *http.Server
	logger     *logging.Logger
	metrics    *metrics.Metrics
	tracer     *tracing.Tracer
}

// New creates a new server instance.
func New(cfg *config.Config, logger *logging.Logger) *Server {
	return NewWithMetrics(cfg, logger, metrics.New())
}

// NewWithMetrics creates a new server instance with custom metrics (useful for testing).
func NewWithMetrics(cfg *config.Config, logger *logging.Logger, metricsInstance *metrics.Metrics) *Server {
	// Set Gin mode based on log level
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Use provided metrics instance

	// Initialize tracing
	tracingConfig := &tracing.Config{
		Enabled:        cfg.Tracing.Enabled,
		ServiceName:    cfg.Tracing.ServiceName,
		Environment:    cfg.Tracing.Environment,
		Exporter:       cfg.Tracing.Exporter,
		JaegerEndpoint: cfg.Tracing.JaegerEndpoint,
		OTLPEndpoint:   cfg.Tracing.OTLPEndpoint,
		OTLPHeaders:    cfg.Tracing.OTLPHeaders,
		SampleRate:     cfg.Tracing.SampleRate,
	}

	tracerInstance, err := tracing.New(tracingConfig)
	if err != nil {
		logger.LogError(err, "Failed to initialize tracing, continuing without tracing")
		tracerInstance = nil
	}

	router := gin.New()

	// Add error handling middleware first
	router.Use(middleware.ErrorHandlerMiddleware(logger))
	router.Use(requestIDMiddleware())

	// Add tracing middleware if enabled
	if tracerInstance != nil {
		router.Use(tracerInstance.GinMiddleware())
		router.Use(tracerInstance.TracingContextMiddleware())
	}

	router.Use(metricsInstance.MetricsMiddleware())
	router.Use(loggingMiddleware(logger))
	router.Use(middleware.ErrorResponseMiddleware())

	// Handle 404 and 405 errors
	router.NoRoute(middleware.NotFoundHandler())
	router.NoMethod(middleware.MethodNotAllowedHandler())

	server := &Server{
		config:  cfg,
		router:  router,
		logger:  logger,
		metrics: metricsInstance,
		tracer:  tracerInstance,
	}

	server.setupRoutes()

	return server
}

// setupRoutes configures all the routes.
func (s *Server) setupRoutes() {
	// Metrics endpoint (Prometheus scraping)
	s.router.GET("/metrics", s.metrics.Handler())

	// Health check endpoints
	health := s.router.Group("/health")
	{
		health.GET("/live", s.handleLiveness)
		health.GET("/ready", s.handleReadiness)
		health.GET("", s.handleHealth) // Basic health endpoint
	}

	// API version group
	v1 := s.router.Group("/api/v1")
	{
		// Status endpoint
		v1.GET("/status", s.handleStatus)

		// Register crypto module routes
		cryptoService := crypto.NewCryptoService()
		cryptoHandler := crypto.NewHandler(cryptoService, s.metrics)
		cryptoHandler.RegisterRoutes(v1)

		// Register text module routes
		textService := text.NewTextService()
		textHandler := text.NewHandler(textService, s.metrics)
		textHandler.RegisterRoutes(v1)

		// Register transform module routes
		transformService := transform.NewTransformService()
		transformHandler := transform.NewHandler(transformService, s.metrics)
		transformHandler.RegisterRoutes(v1)

		// Register ID module routes
		idService := id.NewService()
		idHandler := id.NewHandler(idService, s.metrics)
		idHandler.RegisterRoutes(v1)

		// Register time module routes
		timeService := timeModule.NewService()
		timeHandler := timeModule.NewHandler(timeService, s.metrics)
		timeHandler.RegisterRoutes(v1)

		// Register network module routes
		networkService := network.NewNetworkService()
		networkHandler := network.NewHandler(networkService, s.metrics)
		networkHandler.RegisterRoutes(v1)
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Server.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  constants.DefaultReadTimeout,
		WriteTimeout: constants.DefaultWriteTimeout,
		IdleTimeout:  constants.DefaultIdleTimeout,
	}

	s.logger.Info("Starting server", "addr", addr, "tls", s.config.Server.TLSEnabled)

	if s.config.Server.TLSEnabled {
		// For now, we'll use HTTP. TLS setup would require cert files
		s.logger.Warn("TLS enabled but not implemented yet, falling back to HTTP")
	}

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down server...")

	// Shutdown tracing first
	if s.tracer != nil {
		if err := s.tracer.Shutdown(ctx); err != nil {
			s.logger.LogError(err, "Failed to shutdown tracer")
		}
	}

	// Only shutdown HTTP server if it was started
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}

// GetRouter returns the Gin router for testing purposes.
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// ServeHTTP implements the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// Health check handlers.
func (s *Server) handleHealth(c *gin.Context) {
	versionInfo := version.Get()
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   versionInfo.Service,
	})
}

func (s *Server) handleLiveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "alive",
	})
}

func (s *Server) handleReadiness(c *gin.Context) {
	// For now, always ready. Later we can add dependency checks
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}

func (s *Server) handleStatus(c *gin.Context) {
	versionInfo := version.Get()
	c.JSON(http.StatusOK, gin.H{
		"service": versionInfo.Service,
		"version": versionInfo.Version,
		"status":  "running",
	})
}

// requestIDMiddleware adds a unique request ID to each request.
func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in context and response header
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// loggingMiddleware provides structured logging for HTTP requests with request ID tracing.
func loggingMiddleware(logger *logging.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Get request ID from context
		requestID, _ := c.Get("request_id")

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)
		status := c.Writer.Status()

		// Build log entry with request ID
		logEntry := []any{
			"request_id", requestID,
			"method", c.Request.Method,
			"path", path,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"response_size", c.Writer.Size(),
		}

		// Add query parameters if present (but sanitize sensitive data)
		if raw != "" {
			sanitizedQuery := sanitizeQueryParams(raw)
			if sanitizedQuery != "" {
				logEntry = append(logEntry, "query", sanitizedQuery)
			}
		}

		// Add error information if present
		if len(c.Errors) > 0 {
			logEntry = append(logEntry, "errors", c.Errors.String())
		}

		// Log based on status code
		switch {
		case status >= constants.LogLevelErrorThreshold:
			logger.Error("HTTP request", logEntry...)
		case status >= constants.LogLevelWarningThreshold:
			logger.Warn("HTTP request", logEntry...)
		default:
			logger.Info("HTTP request", logEntry...)
		}
	}
}

// sanitizeQueryParams removes sensitive data from query parameters for logging
func sanitizeQueryParams(query string) string {
	// List of sensitive parameter names that should not be logged
	sensitiveParams := []string{
		"password", "secret", "key", "token", "auth", "api_key",
		"jwt", "bearer", "credential", "private", "hash",
	}

	// Simple sanitization - if any sensitive param is found, don't log query
	queryLower := strings.ToLower(query)
	for _, param := range sensitiveParams {
		if strings.Contains(queryLower, param) {
			return "[REDACTED]"
		}
	}

	return query
}
