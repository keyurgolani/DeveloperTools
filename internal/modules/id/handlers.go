package id

import (
	"net/http"

	"github.com/keyurgolani/DeveloperTools/internal/metrics"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for ID generation operations.
type Handler struct {
	service IDService
	metrics *metrics.Metrics
}

// NewHandler creates a new ID handler.
func NewHandler(service IDService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers ID routes with the router.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	id := router.Group("/id")
	{
		id.POST("/uuid", h.GenerateUUID)
		id.POST("/nanoid", h.GenerateNanoID)
	}
}

// GenerateUUID handles UUID generation requests.
func (h *Handler) GenerateUUID(c *gin.Context) {
	var req UUIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordIDOperation("generate", "uuid", "validation_error")
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

	// Set default count if not provided
	if req.Count <= 0 {
		req.Count = DefaultCount
	}

	uuids, err := h.service.GenerateUUID(req.Version, req.Count)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordIDOperation("generate", "uuid", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"code":    "UUID_GENERATION_FAILED",
				"message": "Failed to generate UUIDs",
				"details": err.Error(),
			},
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordIDOperation("generate", "uuid", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    UUIDResponse{UUIDs: uuids},
	})
}

// GenerateNanoID handles Nano ID generation requests.
func (h *Handler) GenerateNanoID(c *gin.Context) {
	var req NanoIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordIDOperation("generate", "nanoid", "validation_error")
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

	// Set defaults if not provided
	if req.Size <= 0 {
		req.Size = DefaultNanoIDSize
	}
	if req.Count <= 0 {
		req.Count = DefaultCount
	}

	ids, err := h.service.GenerateNanoID(req.Size, req.Count)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordIDOperation("generate", "nanoid", "error")
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": gin.H{
				"code":    "NANOID_GENERATION_FAILED",
				"message": "Failed to generate Nano IDs",
				"details": err.Error(),
			},
		})
		return
	}

	if h.metrics != nil {
		h.metrics.RecordIDOperation("generate", "nanoid", "success")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    NanoIDResponse{IDs: ids},
	})
}
