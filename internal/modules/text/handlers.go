package text

import (
	"net/http"

	"dev-utilities/internal/metrics"
	"dev-utilities/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for text operations
type Handler struct {
	service TextService
	metrics *metrics.Metrics
}

// NewHandler creates a new text handler
func NewHandler(service TextService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers text routes with the router
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	text := router.Group("/text")
	{
		text.POST("/case", h.ConvertCase)
		text.POST("/info", h.AnalyzeText)
		text.POST("/regex", h.TestRegex)
		text.POST("/sort", h.SortText)
	}
	
	data := router.Group("/data")
	{
		data.POST("/json/format", h.FormatJSON)
	}
}

// ConvertCase handles case conversion requests
func (h *Handler) ConvertCase(c *gin.Context) {
	var req CaseConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("case_convert", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := h.service.ConvertCase(req.Content, req.CaseType)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("case_convert", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Case conversion failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTextOperation("case_convert", "success")
	}

	response := CaseConvertResponse{
		Result:   result,
		CaseType: req.CaseType,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// AnalyzeText handles text analysis requests
func (h *Handler) AnalyzeText(c *gin.Context) {
	var req TextAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("analyze", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	info, err := h.service.AnalyzeText(req.Content)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("analyze", "error")
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": apierror.InternalError("Text analysis failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTextOperation("analyze", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    info,
	})
}

// TestRegex handles regex testing requests
func (h *Handler) TestRegex(c *gin.Context) {
	var req RegexTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("regex_test", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := h.service.TestRegex(req.Content, req.Pattern, req.Flags)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("regex_test", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Regex test failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTextOperation("regex_test", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// FormatJSON handles JSON formatting requests
func (h *Handler) FormatJSON(c *gin.Context) {
	var req JSONFormatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("json_format", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := h.service.FormatJSON(req.Content, req.Action, req.Indent)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("json_format", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("JSON formatting failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTextOperation("json_format", "success")
	}

	response := JSONFormatResponse{
		Result: result,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// SortText handles text sorting requests
func (h *Handler) SortText(c *gin.Context) {
	var req TextSortRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("sort", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := h.service.SortText(req.Content, req.Order, req.SortType)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTextOperation("sort", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Text sorting failed", err.Error()),
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTextOperation("sort", "success")
	}

	response := TextSortResponse{
		Result: result,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}