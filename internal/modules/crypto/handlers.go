package crypto

import (
	"github.com/keyurgolani/DeveloperTools/internal/metrics"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for crypto operations.
type Handler struct {
	service CryptoService
	metrics *metrics.Metrics
}

// NewHandler creates a new crypto handler.
func NewHandler(service CryptoService, metrics *metrics.Metrics) *Handler {
	return &Handler{
		service: service,
		metrics: metrics,
	}
}

// RegisterRoutes registers crypto routes with the router.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	crypto := router.Group("/crypto")
	{
		crypto.POST("/hash", h.Hash)
		crypto.POST("/hmac", h.HMAC)
		crypto.POST("/password/hash", h.HashPassword)
		crypto.POST("/password/verify", h.VerifyPassword)
		crypto.POST("/cert/decode", h.DecodeCertificate)
	}
}

// Hash handles hash calculation requests.
func (h *Handler) Hash(c *gin.Context) {
	var req HashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("hash", "unknown", "validation_error")
		}
		apiError := apierror.HandleBindingError(err)
		apierror.RespondWithError(c, apiError)
		return
	}

	hash, err := h.service.Hash(req.Content, req.Algorithm)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("hash", req.Algorithm, "error")
		}
		apiError := apierror.HandleServiceError(err, "Hash calculation")
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordCryptoOperation("hash", req.Algorithm, "success")
	}

	response := HashResponse{
		Hash:      hash,
		Algorithm: req.Algorithm,
	}

	apierror.RespondWithSuccess(c, response)
}

// HMAC handles HMAC generation requests.
func (h *Handler) HMAC(c *gin.Context) {
	var req HMACRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("hmac", "unknown", "validation_error")
		}
		apiError := apierror.HandleBindingError(err)
		apierror.RespondWithError(c, apiError)
		return
	}

	hmac, err := h.service.HMAC(req.Content, req.Key, req.Algorithm)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("hmac", req.Algorithm, "error")
		}
		apiError := apierror.HandleServiceError(err, "HMAC generation")
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordCryptoOperation("hmac", req.Algorithm, "success")
	}

	response := HMACResponse{
		HMAC:      hmac,
		Algorithm: req.Algorithm,
	}

	apierror.RespondWithSuccess(c, response)
}

// HashPassword handles password hashing requests.
func (h *Handler) HashPassword(c *gin.Context) {
	var req PasswordHashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("password_hash", "argon2id", "validation_error")
		}
		apiError := apierror.HandleBindingError(err)
		apierror.RespondWithError(c, apiError)
		return
	}

	hash, err := h.service.HashPassword(req.Password)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("password_hash", "argon2id", "error")
		}
		apiError := apierror.HandleServiceError(err, "Password hashing")
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordCryptoOperation("password_hash", "argon2id", "success")
	}

	response := PasswordHashResponse{
		Hash: hash,
	}

	apierror.RespondWithSuccess(c, response)
}

// VerifyPassword handles password verification requests.
func (h *Handler) VerifyPassword(c *gin.Context) {
	var req PasswordVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("password_verify", "argon2id", "validation_error")
		}
		apiError := apierror.HandleBindingError(err)
		apierror.RespondWithError(c, apiError)
		return
	}

	valid := h.service.VerifyPassword(req.Password, req.Hash)

	if h.metrics != nil {
		status := "success"
		if !valid {
			status = "invalid_password"
		}
		h.metrics.RecordCryptoOperation("password_verify", "argon2id", status)
	}

	response := PasswordVerifyResponse{
		Valid: valid,
	}

	apierror.RespondWithSuccess(c, response)
}

// DecodeCertificate handles certificate decoding requests.
func (h *Handler) DecodeCertificate(c *gin.Context) {
	var req CertificateDecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("cert_decode", "x509", "validation_error")
		}
		apiError := apierror.HandleBindingError(err)
		apierror.RespondWithError(c, apiError)
		return
	}

	certInfo, err := h.service.DecodeCertificate(req.Certificate)
	if err != nil {
		if h.metrics != nil {
			h.metrics.RecordCryptoOperation("cert_decode", "x509", "error")
		}
		apiError := apierror.NewValidationError("Certificate decoding failed", err.Error())
		apierror.RespondWithError(c, apiError)
		return
	}

	if h.metrics != nil {
		h.metrics.RecordCryptoOperation("cert_decode", "x509", "success")
	}

	response := CertificateDecodeResponse{
		Certificate: certInfo,
	}

	apierror.RespondWithSuccess(c, response)
}
