package time

import (
	"net/http"

	"github.com/keyurgolani/DeveloperTools/internal/metrics"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for time operations.
type Handler struct {
	service TimeService
	metrics *metrics.Metrics
}

// NewHandler creates a new time handler.
func NewHandler(service TimeService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers time routes with the router.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	time := router.Group("/time")
	{
		time.POST("/convert", h.ConvertTime)
		time.GET("/now", h.GetCurrentTime)
	}
}

// ConvertTime handles time conversion requests.
func (h *Handler) ConvertTime(c *gin.Context) {
	var req TimeConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTimeOperation("convert", "validation_error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"code":    "INVALID_REQUEST",
				"message": "Invalid request format",
				"details": err.Error(),
			},
		})
		return
	}

	result, err := h.service.ConvertTime(req.Input, req.InputFormat, req.OutputFormat)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTimeOperation("convert", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"code":    "TIME_CONVERSION_FAILED",
				"message": "Failed to convert time",
				"details": err.Error(),
			},
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTimeOperation("convert", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    TimeConvertResponse{Result: result},
	})
}

// GetCurrentTime handles current time requests.
func (h *Handler) GetCurrentTime(c *gin.Context) {
	timeResponse, err := h.service.GetCurrentTime()
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTimeOperation("current", "error")
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"code":    "TIME_RETRIEVAL_FAILED",
				"message": "Failed to retrieve current time",
				"details": err.Error(),
			},
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTimeOperation("current", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    timeResponse,
	})
}
