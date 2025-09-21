package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"dev-utilities/internal/logging"
	"dev-utilities/pkg/apierror"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorHandlerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	// Create a test logger
	logger := logging.New("debug")
	
	tests := []struct {
		name           string
		handler        gin.HandlerFunc
		expectedStatus int
		expectedError  string
	}{
		{
			name: "handles panic with string",
			handler: func(c *gin.Context) {
				panic("test panic")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "INTERNAL_ERROR",
		},
		{
			name: "handles panic with error",
			handler: func(c *gin.Context) {
				panic(errors.New("test error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "INTERNAL_ERROR",
		},
		{
			name: "normal request passes through",
			handler: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.New()
			
			// Add request ID middleware first
			router.Use(func(c *gin.Context) {
				c.Set("request_id", "test-request-id")
				c.Header("X-Request-ID", "test-request-id")
				c.Next()
			})
			
			// Add error handling middleware
			router.Use(ErrorHandlerMiddleware(logger))
			router.GET("/test", tt.handler)
			
			// Make request
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			if tt.expectedError != "" {
				var response apierror.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				
				assert.False(t, response.Success)
				assert.Equal(t, tt.expectedError, response.Error.Code)
				assert.Equal(t, "test-request-id", w.Header().Get("X-Request-ID"))
			}
		})
	}
}

func TestErrorResponseMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	tests := []struct {
		name           string
		handler        gin.HandlerFunc
		expectedStatus int
		expectedError  string
	}{
		{
			name: "handles APIError in context",
			handler: func(c *gin.Context) {
				apiErr := apierror.NewValidationError("test validation error", "details")
				c.Error(apiErr)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name: "handles generic error in context",
			handler: func(c *gin.Context) {
				c.Error(errors.New("generic error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "INTERNAL_ERROR",
		},
		{
			name: "no error passes through",
			handler: func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, router := gin.CreateTestContext(w)
			
			// Add middleware
			router.Use(ErrorResponseMiddleware())
			router.GET("/test", tt.handler)
			
			// Make request
			req := httptest.NewRequest("GET", "/test", nil)
			c.Request = req
			router.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			if tt.expectedError != "" {
				var response apierror.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				
				assert.False(t, response.Success)
				assert.Equal(t, tt.expectedError, response.Error.Code)
			}
		})
	}
}

func TestNotFoundHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	w := httptest.NewRecorder()
	router := gin.New()
	
	// Set up 404 handler
	router.NoRoute(NotFoundHandler())
	
	// Make request to non-existent endpoint
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusNotFound, w.Code)
	
	var response apierror.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.False(t, response.Success)
	assert.Equal(t, "NOT_FOUND", response.Error.Code)
	assert.Equal(t, "Endpoint not found", response.Error.Message)
}

func TestMethodNotAllowedHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	// Test the handler directly since Gin's NoMethod behavior is complex
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// Call the handler directly
	handler := MethodNotAllowedHandler()
	handler(c)
	
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	
	var response apierror.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.False(t, response.Success)
	assert.Equal(t, "METHOD_NOT_ALLOWED", response.Error.Code)
	assert.Equal(t, "Method not allowed", response.Error.Message)
}