package crypto

import (
	"net/http"

	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// handleRequestWithMetrics is a helper function to reduce code duplication.
func (h *MetricsAwareHandler) handleRequestWithMetrics(
	c *gin.Context,
	operation, algorithm string,
	req interface{},
	handler func() (interface{}, error),
) {
	if err := c.ShouldBindJSON(req); err != nil {
		h.metrics.RecordCryptoOperation(operation, algorithm, "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	result, err := handler()
	if err != nil {
		h.metrics.RecordCryptoOperation(operation, algorithm, "error")
		statusCode := http.StatusInternalServerError
		if operation == "cert_decode" {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{
			"error": apierror.ValidationError(operation+" failed", err.Error()),
		})
		return
	}

	h.metrics.RecordCryptoOperation(operation, algorithm, "success")
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// MetricsAwareHandler handles HTTP requests for crypto operations with metrics.
type MetricsAwareHandler struct {
	service CryptoService
	metrics *metrics.Metrics
}

// NewMetricsAwareHandler creates a new crypto handler with metrics support.
func NewMetricsAwareHandler(service CryptoService, metrics *metrics.Metrics) *MetricsAwareHandler {
	return &MetricsAwareHandler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers crypto routes with the router.
func (h *MetricsAwareHandler) RegisterRoutes(router *gin.RouterGroup) {
	crypto := router.Group("/crypto")
	{
		crypto.POST("/hash", h.Hash)
		crypto.POST("/hmac", h.HMAC)
		crypto.POST("/password/hash", h.HashPassword)
		crypto.POST("/password/verify", h.VerifyPassword)
		crypto.POST("/cert/decode", h.DecodeCertificate)
	}
}

// Hash handles hash calculation requests with metrics.
func (h *MetricsAwareHandler) Hash(c *gin.Context) {
	var req HashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.metrics.RecordCryptoOperation("hash", req.Algorithm, "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	hash, err := h.service.Hash(req.Content, req.Algorithm)
	if err != nil {
		h.metrics.RecordCryptoOperation("hash", req.Algorithm, "error")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": apierror.InternalError("Hash calculation failed", err.Error()),
		})
		return
	}

	h.metrics.RecordCryptoOperation("hash", req.Algorithm, "success")

	response := HashResponse{
		Hash:      hash,
		Algorithm: req.Algorithm,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// HMAC handles HMAC generation requests with metrics.
func (h *MetricsAwareHandler) HMAC(c *gin.Context) {
	var req HMACRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.metrics.RecordCryptoOperation("hmac", req.Algorithm, "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	hmac, err := h.service.HMAC(req.Content, req.Key, req.Algorithm)
	if err != nil {
		h.metrics.RecordCryptoOperation("hmac", req.Algorithm, "error")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": apierror.InternalError("HMAC generation failed", err.Error()),
		})
		return
	}

	h.metrics.RecordCryptoOperation("hmac", req.Algorithm, "success")

	response := HMACResponse{
		HMAC:      hmac,
		Algorithm: req.Algorithm,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// HashPassword handles password hashing requests with metrics.
func (h *MetricsAwareHandler) HashPassword(c *gin.Context) {
	var req PasswordHashRequest
	h.handleRequestWithMetrics(c, "password_hash", "argon2id", &req, func() (interface{}, error) {
		hash, err := h.service.HashPassword(req.Password)
		if err != nil {
			return nil, err
		}
		return PasswordHashResponse{Hash: hash}, nil
	})
}

// VerifyPassword handles password verification requests with metrics.
func (h *MetricsAwareHandler) VerifyPassword(c *gin.Context) {
	var req PasswordVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.metrics.RecordCryptoOperation("password_verify", "argon2id", "validation_error")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": apierror.ValidationError("Invalid request", err.Error()),
		})
		return
	}

	valid := h.service.VerifyPassword(req.Password, req.Hash)

	// Record success regardless of verification result
	h.metrics.RecordCryptoOperation("password_verify", "argon2id", "success")

	response := PasswordVerifyResponse{
		Valid: valid,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// DecodeCertificate handles certificate decoding requests with metrics.
func (h *MetricsAwareHandler) DecodeCertificate(c *gin.Context) {
	var req CertificateDecodeRequest
	h.handleRequestWithMetrics(c, "cert_decode", "x509", &req, func() (interface{}, error) {
		certInfo, err := h.service.DecodeCertificate(req.Certificate)
		if err != nil {
			return nil, err
		}
		return CertificateDecodeResponse{Certificate: certInfo}, nil
	})
}
