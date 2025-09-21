package apierror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIError_HTTPStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		error    *APIError
		expected int
	}{
		{
			name:     "validation error returns 400",
			error:    NewValidationError("test", "details"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "authentication error returns 401",
			error:    NewAuthenticationError("test"),
			expected: http.StatusUnauthorized,
		},
		{
			name:     "authorization error returns 403",
			error:    NewAuthorizationError("test"),
			expected: http.StatusForbidden,
		},
		{
			name:     "rate limit error returns 429",
			error:    NewRateLimitError("test"),
			expected: http.StatusTooManyRequests,
		},
		{
			name:     "service unavailable error returns 503",
			error:    NewServiceUnavailableError("test"),
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "internal error returns 500",
			error:    NewInternalError("test"),
			expected: http.StatusInternalServerError,
		},
		{
			name: "unknown error code returns 500",
			error: &APIError{
				Code:    "UNKNOWN_ERROR",
				Message: "test",
			},
			expected: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode := tt.error.HTTPStatusCode()
			assert.Equal(t, tt.expected, statusCode)
		})
	}
}

func TestRespondWithError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		error          *APIError
		expectedStatus int
		expectedBody   ErrorResponse
		requestID      string
	}{
		{
			name:           "validation error response",
			error:          NewValidationError("Invalid input", "Field is required"),
			expectedStatus: http.StatusBadRequest,
			expectedBody: ErrorResponse{
				Success: false,
				Error: APIError{
					Code:    CodeValidationError,
					Message: "Invalid input",
					Details: "Field is required",
				},
			},
		},
		{
			name:           "internal error response",
			error:          NewInternalError("Something went wrong"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: ErrorResponse{
				Success: false,
				Error: APIError{
					Code:    CodeInternalError,
					Message: "Something went wrong",
				},
			},
		},
		{
			name:           "error with request ID",
			error:          NewValidationError("Test error", ""),
			expectedStatus: http.StatusBadRequest,
			requestID:      "test-request-id",
			expectedBody: ErrorResponse{
				Success: false,
				Error: APIError{
					Code:    CodeValidationError,
					Message: "Test error",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set request ID if provided
			if tt.requestID != "" {
				c.Set("request_id", tt.requestID)
			}

			RespondWithError(c, tt.error)

			assert.Equal(t, tt.expectedStatus, w.Code)

			// Check request ID header if set
			if tt.requestID != "" {
				assert.Equal(t, tt.requestID, w.Header().Get("X-Request-ID"))
			}

			// Parse response body
			var response ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedBody, response)
		})
	}
}

func TestRespondWithSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		data        interface{}
		requestID   string
		expectedBody SuccessResponse
	}{
		{
			name: "simple success response",
			data: map[string]string{"result": "success"},
			expectedBody: SuccessResponse{
				Success: true,
				Data:    map[string]interface{}{"result": "success"},
			},
		},
		{
			name:      "success response with request ID",
			data:      "test data",
			requestID: "test-request-id",
			expectedBody: SuccessResponse{
				Success: true,
				Data:    "test data",
			},
		},
		{
			name: "success response with nil data",
			data: nil,
			expectedBody: SuccessResponse{
				Success: true,
				Data:    nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set request ID if provided
			if tt.requestID != "" {
				c.Set("request_id", tt.requestID)
			}

			RespondWithSuccess(c, tt.data)

			assert.Equal(t, http.StatusOK, w.Code)

			// Check request ID header if set
			if tt.requestID != "" {
				assert.Equal(t, tt.requestID, w.Header().Get("X-Request-ID"))
			}

			// Parse response body
			var response SuccessResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedBody, response)
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name     string
		function func() *APIError
		expected APIError
	}{
		{
			name:     "NewValidationError",
			function: func() *APIError { return NewValidationError("test message", "test details") },
			expected: APIError{Code: CodeValidationError, Message: "test message", Details: "test details"},
		},
		{
			name:     "NewAuthenticationError",
			function: func() *APIError { return NewAuthenticationError("auth failed") },
			expected: APIError{Code: CodeAuthenticationError, Message: "auth failed"},
		},
		{
			name:     "NewAuthorizationError",
			function: func() *APIError { return NewAuthorizationError("not authorized") },
			expected: APIError{Code: CodeAuthorizationError, Message: "not authorized"},
		},
		{
			name:     "NewRateLimitError",
			function: func() *APIError { return NewRateLimitError("rate limited") },
			expected: APIError{Code: CodeRateLimitError, Message: "rate limited"},
		},
		{
			name:     "NewInternalError",
			function: func() *APIError { return NewInternalError("internal error") },
			expected: APIError{Code: CodeInternalError, Message: "internal error"},
		},
		{
			name:     "NewServiceUnavailableError",
			function: func() *APIError { return NewServiceUnavailableError("service down") },
			expected: APIError{Code: CodeServiceUnavailable, Message: "service down"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function()
			assert.Equal(t, tt.expected, *result)
		})
	}
}

func TestHandleBindingError(t *testing.T) {
	testErr := assert.AnError
	result := HandleBindingError(testErr)

	expected := &APIError{
		Code:    CodeValidationError,
		Message: "Invalid request format",
		Details: testErr.Error(),
	}

	assert.Equal(t, expected, result)
}

func TestHandleServiceError(t *testing.T) {
	testErr := assert.AnError
	operation := "test operation"
	result := HandleServiceError(testErr, operation)

	expected := &APIError{
		Code:    CodeInternalError,
		Message: operation + " failed",
		Details: testErr.Error(),
	}

	assert.Equal(t, expected, result)
}