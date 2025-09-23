package apierror

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIError represents a standardized API error.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// ErrorResponse represents the standard error response format.
type ErrorResponse struct {
	Success bool     `json:"success"`
	Error   APIError `json:"error"`
}

// SuccessResponse represents the standard success response format.
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

// Common error codes.
const (
	CodeValidationError     = "VALIDATION_ERROR"
	CodeAuthenticationError = "AUTHENTICATION_ERROR"
	CodeAuthorizationError  = "AUTHORIZATION_ERROR"
	CodeRateLimitError      = "RATE_LIMIT_ERROR"
	CodeInternalError       = "INTERNAL_ERROR"
	CodeServiceUnavailable  = "SERVICE_UNAVAILABLE"
)

// NewValidationError creates a validation error.
func NewValidationError(message, details string) *APIError {
	return &APIError{
		Code:    CodeValidationError,
		Message: message,
		Details: details,
	}
}

// NewAuthenticationError creates an authentication error.
func NewAuthenticationError(message string) *APIError {
	return &APIError{
		Code:    CodeAuthenticationError,
		Message: message,
	}
}

// NewAuthorizationError creates an authorization error.
func NewAuthorizationError(message string) *APIError {
	return &APIError{
		Code:    CodeAuthorizationError,
		Message: message,
	}
}

// NewRateLimitError creates a rate limit error.
func NewRateLimitError(message string) *APIError {
	return &APIError{
		Code:    CodeRateLimitError,
		Message: message,
	}
}

// NewInternalError creates an internal server error.
func NewInternalError(message string) *APIError {
	return &APIError{
		Code:    CodeInternalError,
		Message: message,
	}
}

// ValidationError creates a validation error with details.
func ValidationError(message, details string) *APIError {
	return NewValidationError(message, details)
}

// InternalError creates an internal error with details.
func InternalError(message, details string) *APIError {
	return &APIError{
		Code:    CodeInternalError,
		Message: message,
		Details: details,
	}
}

// NewServiceUnavailableError creates a service unavailable error.
func NewServiceUnavailableError(message string) *APIError {
	return &APIError{
		Code:    CodeServiceUnavailable,
		Message: message,
	}
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

// HTTPStatusCode returns the appropriate HTTP status code for the error.
func (e *APIError) HTTPStatusCode() int {
	switch e.Code {
	case CodeValidationError:
		return http.StatusBadRequest
	case CodeAuthenticationError:
		return http.StatusUnauthorized
	case CodeAuthorizationError:
		return http.StatusForbidden
	case CodeRateLimitError:
		return http.StatusTooManyRequests
	case CodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case "NOT_FOUND":
		return http.StatusNotFound
	case "METHOD_NOT_ALLOWED":
		return http.StatusMethodNotAllowed
	default:
		return http.StatusInternalServerError
	}
}

// RespondWithError sends a standardized error response.
func RespondWithError(c *gin.Context, apiError *APIError) {
	statusCode := apiError.HTTPStatusCode()

	// Add request ID to error context if available
	if requestID, exists := c.Get("request_id"); exists {
		c.Header("X-Request-ID", requestID.(string))
	}

	response := ErrorResponse{
		Success: false,
		Error:   *apiError,
	}

	c.JSON(statusCode, response)
}

// RespondWithSuccess sends a standardized success response.
func RespondWithSuccess(c *gin.Context, data interface{}) {
	// Add request ID to response header if available
	if requestID, exists := c.Get("request_id"); exists {
		c.Header("X-Request-ID", requestID.(string))
	}

	response := SuccessResponse{
		Success: true,
		Data:    data,
	}

	c.JSON(http.StatusOK, response)
}

// HandleBindingError creates a validation error from Gin binding errors.
func HandleBindingError(err error) *APIError {
	return NewValidationError("Invalid request format", err.Error())
}

// HandleServiceError creates an appropriate error based on the service error.
func HandleServiceError(err error, operation string) *APIError {
	// For now, treat all service errors as internal errors
	// In the future, we could have typed errors from services
	return InternalError(operation+" failed", err.Error())
}
