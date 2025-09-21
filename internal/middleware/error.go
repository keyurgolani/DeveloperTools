package middleware

import (
	"runtime/debug"

	"dev-utilities/internal/logging"
	"dev-utilities/pkg/apierror"

	"github.com/gin-gonic/gin"
)

// ErrorHandlerMiddleware provides centralized error handling
func ErrorHandlerMiddleware(logger *logging.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Get request ID for context
		requestID, _ := c.Get("request_id")
		
		// Log the panic with stack trace
		logger.Error("Panic recovered",
			"request_id", requestID,
			"panic", recovered,
			"stack", string(debug.Stack()),
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
		)
		
		// Create internal server error
		apiError := apierror.InternalError("Internal server error", "An unexpected error occurred")
		apierror.RespondWithError(c, apiError)
	})
}

// ErrorResponseMiddleware handles errors that were added to the Gin context
func ErrorResponseMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		// Check if there are any errors in the context
		if len(c.Errors) > 0 {
			// Get the last error (most recent)
			err := c.Errors.Last()
			
			// Check if it's already an APIError
			if apiErr, ok := err.Err.(*apierror.APIError); ok {
				apierror.RespondWithError(c, apiErr)
				return
			}
			
			// Otherwise, create a generic internal error
			apiError := apierror.InternalError("Request processing failed", err.Error())
			apierror.RespondWithError(c, apiError)
		}
	}
}

// NotFoundHandler handles 404 errors
func NotFoundHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiError := &apierror.APIError{
			Code:    "NOT_FOUND",
			Message: "Endpoint not found",
			Details: "The requested endpoint does not exist",
		}
		apierror.RespondWithError(c, apiError)
	}
}

// MethodNotAllowedHandler handles 405 errors
func MethodNotAllowedHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiError := &apierror.APIError{
			Code:    "METHOD_NOT_ALLOWED",
			Message: "Method not allowed",
			Details: "The HTTP method is not allowed for this endpoint",
		}
		apierror.RespondWithError(c, apiError)
	}
}