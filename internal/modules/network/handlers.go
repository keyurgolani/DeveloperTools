package network

import (
	"net/http"

	"dev-utilities/internal/metrics"
	"dev-utilities/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for network operations
type Handler struct {
	service NetworkService
	metrics *metrics.Metrics
}

// NewHandler creates a new network handler
func NewHandler(service NetworkService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers network routes with the router
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

// URLOperation handles URL parsing and building operations
func (h *Handler) URLOperation(c *gin.Context) {
	var req URLOperationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("url_operation", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	switch req.Action {
	case "parse":
		if req.URL == "" {
			if h.metrics != nil {
				h.metrics.RecordNetworkOperation("url_parse", "validation_error")
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error": apierror.ValidationError("URL is required for parse operation", ""),
			})
			return
		}

		parts, err := h.service.ParseURL(req.URL)
		if err != nil {
			if h.metrics != nil {
				h.metrics.RecordNetworkOperation("url_parse", "error")
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error": apierror.ValidationError("URL parsing failed", err.Error()),
			})
			return
		}

		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("url_parse", "success")
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    parts,
		})

	case "build":
		if req.Scheme == "" || req.Host == "" {
			if h.metrics != nil {
				h.metrics.RecordNetworkOperation("url_build", "validation_error")
			}
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
			if h.metrics != nil {
				h.metrics.RecordNetworkOperation("url_build", "error")
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error": apierror.ValidationError("URL building failed", err.Error()),
			})
			return
		}

		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("url_build", "success")
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    map[string]string{"url": url},
		})

	default:
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("url_operation", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid action", "Action must be 'parse' or 'build'"),
		})
	}
}

// GetHeaders handles HTTP header inspection requests
func (h *Handler) GetHeaders(c *gin.Context) {
	var req HeadersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("headers", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	headers, err := h.service.GetHeaders(req.URL)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("headers", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Header inspection failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordNetworkOperation("headers", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    headers,
	})
}

// DNSLookup handles DNS lookup requests
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

// AnalyzeIP handles IP address analysis requests
func (h *Handler) AnalyzeIP(c *gin.Context) {
	var req IPAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("ip_analysis", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	info, err := h.service.AnalyzeIP(req.IP)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordNetworkOperation("ip_analysis", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("IP analysis failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordNetworkOperation("ip_analysis", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    info,
	})
}