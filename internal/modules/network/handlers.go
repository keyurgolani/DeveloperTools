package network

import (
	"net/http"

	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for network operations.
type Handler struct {
	service NetworkService
	metrics *metrics.Metrics
}

// NewHandler creates a new network handler.
func NewHandler(service NetworkService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers network routes with the router.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	// Web utilities
	web := router.Group("/web")
	{
		web.POST("/url", h.URLOperation)
	}

	// Network utilities
	network := router.Group("/network")
	{
		network.POST("/headers", h.GetHeaders)
		network.POST("/dns", h.DNSLookup)
		network.POST("/ip", h.AnalyzeIP)
	}
}

// URLOperation handles URL parsing and building operations.
func (h *Handler) URLOperation(c *gin.Context) {
	var req URLOperationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.recordMetrics("url_operation", "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	switch req.Action {
	case "parse":
		h.handleURLParse(c, req)
	case "build":
		h.handleURLBuild(c, req)
	default:
		h.recordMetrics("url_operation", "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid action", "Action must be 'parse' or 'build'"),
		})
	}
}

// handleURLParse handles URL parsing operations.
func (h *Handler) handleURLParse(c *gin.Context, req URLOperationRequest) {
	if req.URL == "" {
		h.recordMetrics("url_parse", "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("URL is required for parse operation", ""),
		})
		return
	}

	parts, err := h.service.ParseURL(req.URL)
	if err != nil {
		h.recordMetrics("url_parse", "error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("URL parsing failed", err.Error()),
		})
		return
	}

	h.recordMetrics("url_parse", "success")
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    parts,
	})
}

// handleURLBuild handles URL building operations.
func (h *Handler) handleURLBuild(c *gin.Context, req URLOperationRequest) {
	if req.Scheme == "" || req.Host == "" {
		h.recordMetrics("url_build", "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Scheme and host are required for build operation", ""),
		})
		return
	}

	parts := &URLParts{
		Scheme:   req.Scheme,
		Host:     req.Host,
		Path:     req.Path,
		Query:    req.Query,
		Fragment: req.Fragment,
	}

	url, err := h.service.BuildURL(parts)
	if err != nil {
		h.recordMetrics("url_build", "error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("URL building failed", err.Error()),
		})
		return
	}

	h.recordMetrics("url_build", "success")
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    map[string]string{"url": url},
	})
}

// recordMetrics records metrics if metrics service is available.
func (h *Handler) recordMetrics(operation, status string) {
	if h.metrics != nil {
		h.metrics.RecordNetworkOperation(operation, status)
	}
}

// GetHeaders handles HTTP header inspection requests.
func (h *Handler) GetHeaders(c *gin.Context) {
	var req HeadersRequest
	h.handleNetworkOperation(c, &req, "headers", func() (interface{}, error) {
		return h.service.GetHeaders(req.URL)
	}, "Header inspection failed")
}

// DNSLookup handles DNS lookup requests.
func (h *Handler) DNSLookup(c *gin.Context) {
	var req DNSLookupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("dns_lookup", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := h.service.DNSLookup(req.Domain, req.RecordType)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("dns_lookup", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("DNS lookup failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordNetworkOperation("dns_lookup", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// AnalyzeIP handles IP address analysis requests.
func (h *Handler) AnalyzeIP(c *gin.Context) {
	var req IPAnalysisRequest
	h.handleNetworkOperation(c, &req, "ip_analysis", func() (interface{}, error) {
		return h.service.AnalyzeIP(req.IP)
	}, "IP analysis failed")
}

// Helper function to handle common network operation pattern.
func (h *Handler) handleNetworkOperation(
	c *gin.Context, req interface{}, operation string,
	serviceCall func() (interface{}, error), errorMessage string,
) {
	if err := c.ShouldBindJSON(req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation(operation, "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := serviceCall()
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation(operation, "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError(errorMessage, err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordNetworkOperation(operation, "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}
