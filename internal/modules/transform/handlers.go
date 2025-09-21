package transform

import (
	"dev-utilities/internal/metrics"
	"dev-utilities/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for transform operations
type Handler struct {
	service TransformService
	metrics *metrics.Metrics
}

// NewHandler creates a new transform handler
func NewHandler(service TransformService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers all transform routes
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	transform := router.Group("/transform")
	{
		transform.POST("/base64", h.handleBase64)
		transform.POST("/url", h.handleURL)
		transform.POST("/jwt/decode", h.handleJWTDecode)
		transform.POST("/compress", h.handleCompress)
	}
}

// handleBase64 handles Base64 encoding/decoding requests
func (h *Handler) handleBase64(c *gin.Context) {
	var req Base64Request
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("unknown", "base64", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid request", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	var result string
	var err error

	switch req.Action {
	case "encode":
		result = h.service.Base64Encode(req.Content, req.URLSafe)
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("encode", "base64", "success")
		}
	case "decode":
		result, err = h.service.Base64Decode(req.Content, req.URLSafe)
		if err != nil {
			if h.metrics != nil {
				h.metrics.RecordTransformOperation("decode", "base64", "error")
			}
			apiError := apierror.NewValidationError("Base64 decode failed", err.Error())
			apierror.RespondWithError(c, apiError)
			return
		}
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("decode", "base64", "success")
		}
	default:
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("unknown", "base64", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid action", "action must be 'encode' or 'decode'")
		apierror.RespondWithError(c, apiError)
		return
	}

	response := Base64Response{Result: result}
	apierror.RespondWithSuccess(c, response)
}

// handleURL handles URL encoding/decoding requests
func (h *Handler) handleURL(c *gin.Context) {
	var req URLEncodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("unknown", "url", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid request", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	var result string
	var err error

	switch req.Action {
	case "encode":
		result = h.service.URLEncode(req.Content)
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("encode", "url", "success")
		}
	case "decode":
		result, err = h.service.URLDecode(req.Content)
		if err != nil {
			if h.metrics != nil {
				h.metrics.RecordTransformOperation("decode", "url", "error")
			}
			apiError := apierror.NewValidationError("URL decode failed", err.Error())
			apierror.RespondWithError(c, apiError)
			return
		}
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("decode", "url", "success")
		}
	default:
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("unknown", "url", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid action", "action must be 'encode' or 'decode'")
		apierror.RespondWithError(c, apiError)
		return
	}

	response := URLEncodeResponse{Result: result}
	apierror.RespondWithSuccess(c, response)
}

// handleJWTDecode handles JWT decoding requests
func (h *Handler) handleJWTDecode(c *gin.Context) {
	var req JWTDecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("decode", "jwt", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid request", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	result, err := h.service.DecodeJWT(req.Token)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("decode", "jwt", "error")
		}
		apiError := apierror.NewValidationError("JWT decode failed", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTransformOperation("decode", "jwt", "success")
	}

	apierror.RespondWithSuccess(c, result)
}

// handleCompress handles compression/decompression requests
func (h *Handler) handleCompress(c *gin.Context) {
	var req CompressionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation("unknown", "compression", "validation_error")
		}
		apiError := apierror.NewValidationError("Invalid request", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	result, err := h.service.Compress(req.Content, req.Algorithm, req.Action)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordTransformOperation(req.Action, req.Algorithm, "error")
		}
		apiError := apierror.NewValidationError("Compression operation failed", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordTransformOperation(req.Action, req.Algorithm, "success")
	}

	response := CompressionResponse{Result: result}
	apierror.RespondWithSuccess(c, response)
}