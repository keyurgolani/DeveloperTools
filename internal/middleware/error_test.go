package middleware_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/middleware"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorHandlerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logging.New("debug")
	tests := getErrorHandlerTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeErrorHandlerTest(t, logger, tt)
		})
	}
}

func getErrorHandlerTestCases() []struct {
	name           string
	handler        gin.HandlerFunc
	expectedStatus int
	expectedError  string
} {
	return []struct {
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
}

func executeErrorHandlerTest(t *testing.T, logger *logging.Logger, tt struct {
	name           string
	handler        gin.HandlerFunc
	expectedStatus int
	expectedError  string
},
) {
	w := httptest.NewRecorder()
	router := setupErrorHandlerRouter(logger, tt.handler)

	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	if tt.expectedError != "" {
		verifyErrorResponse(t, w, tt.expectedError)
	}
}

func setupErrorHandlerRouter(logger *logging.Logger, handler gin.HandlerFunc) *gin.Engine {
	router := gin.New()

	// Add request ID middleware first
	router.Use(func(c *gin.Context) {
		c.Set("request_id", "test-request-id")
		c.Header("X-Request-ID", "test-request-id")
		c.Next()
	})

	// Add error handling middleware
	router.Use(middleware.ErrorHandlerMiddleware(logger))
	router.GET("/test", handler)
	return router
}

func verifyErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedError string) {
	var response apierror.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.False(t, response.Success)
	assert.Equal(t, expectedError, response.Error.Code)
	assert.Equal(t, "test-request-id", w.Header().Get("X-Request-ID"))
}

func TestErrorResponseMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := getErrorResponseTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeErrorResponseTest(t, tt)
		})
	}
}

func getErrorResponseTestCases() []struct {
	name           string
	handler        gin.HandlerFunc
	expectedStatus int
	expectedError  string
} {
	return []struct {
		name           string
		handler        gin.HandlerFunc
		expectedStatus int
		expectedError  string
	}{
		{
			name: "handles APIError in context",
			handler: func(c *gin.Context) {
				apiErr := apierror.NewValidationError("test validation error", "details")
				_ = c.Error(apiErr)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name: "handles generic error in context",
			handler: func(c *gin.Context) {
				_ = c.Error(errors.New("generic error"))
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
}

func executeErrorResponseTest(t *testing.T, tt struct {
	name           string
	handler        gin.HandlerFunc
	expectedStatus int
	expectedError  string
},
) {
	w := httptest.NewRecorder()
	c, router := gin.CreateTestContext(w)

	router.Use(middleware.ErrorResponseMiddleware())
	router.GET("/test", tt.handler)

	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)
	if tt.expectedError != "" {
		verifyErrorResponseCode(t, w, tt.expectedError)
	}
}

func verifyErrorResponseCode(t *testing.T, w *httptest.ResponseRecorder, expectedError string) {
	var response apierror.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.False(t, response.Success)
	assert.Equal(t, expectedError, response.Error.Code)
}

func TestNotFoundHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	router := gin.New()

	// Set up 404 handler
	router.NoRoute(middleware.NotFoundHandler())

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
	handler := middleware.MethodNotAllowedHandler()
	handler(c)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var response apierror.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.False(t, response.Success)
	assert.Equal(t, "METHOD_NOT_ALLOWED", response.Error.Code)
	assert.Equal(t, "Method not allowed", response.Error.Message)
}
