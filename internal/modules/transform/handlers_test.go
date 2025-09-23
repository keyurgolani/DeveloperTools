package transform_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/keyurgolani/DeveloperTools/internal/modules/transform"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	service := NewTransformService()
	handler := NewHandler(service, nil) // Pass nil for metrics in tests

	v1 := router.Group("/api/v1")
	handler.RegisterRoutes(v1)

	return router
}

func TestHandler_Base64(t *testing.T) {
	router := setupTestRouter()
	tests := getBase64HandlerTestCases()
	executeBase64Tests(t, router, tests)
}

// getBase64HandlerTestCases returns test cases for Base64 handler testing.
func getBase64HandlerTestCases() []struct { //nolint:funlen // test data structure
	name           string
	request        Base64Request
	expectedStatus int
	expectedResult string
	expectError    bool
} {
	return []struct {
		name           string
		request        Base64Request
		expectedStatus int
		expectedResult string
		expectError    bool
	}{
		{
			name: "encode standard base64",
			request: Base64Request{
				Content: "hello world",
				Action:  "encode",
				URLSafe: false,
			},
			expectedStatus: http.StatusOK,
			expectedResult: "aGVsbG8gd29ybGQ=",
			expectError:    false,
		},
		{
			name: "encode url-safe base64",
			request: Base64Request{
				Content: "hello>world?",
				Action:  "encode",
				URLSafe: true,
			},
			expectedStatus: http.StatusOK,
			expectedResult: "aGVsbG8-d29ybGQ_",
			expectError:    false,
		},
		{
			name: "decode standard base64",
			request: Base64Request{
				Content: "aGVsbG8gd29ybGQ=",
				Action:  "decode",
				URLSafe: false,
			},
			expectedStatus: http.StatusOK,
			expectedResult: "hello world",
			expectError:    false,
		},
		{
			name: "decode url-safe base64",
			request: Base64Request{
				Content: "aGVsbG8-d29ybGQ_",
				Action:  "decode",
				URLSafe: true,
			},
			expectedStatus: http.StatusOK,
			expectedResult: "hello>world?",
			expectError:    false,
		},
		{
			name: "invalid action",
			request: Base64Request{
				Content: "hello world",
				Action:  "invalid",
				URLSafe: false,
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "invalid base64 decode",
			request: Base64Request{
				Content: "invalid!!!",
				Action:  "decode",
				URLSafe: false,
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}
}

func TestHandler_URL(t *testing.T) {
	router := setupTestRouter()

	tests := []struct {
		name           string
		request        URLEncodeRequest
		expectedStatus int
		expectedResult string
		expectError    bool
	}{
		{
			name: "encode URL",
			request: URLEncodeRequest{
				Content: "hello world",
				Action:  "encode",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "hello+world",
			expectError:    false,
		},
		{
			name: "decode URL",
			request: URLEncodeRequest{
				Content: "hello+world",
				Action:  "decode",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "hello world",
			expectError:    false,
		},
		{
			name: "encode special characters",
			request: URLEncodeRequest{
				Content: "hello@world.com",
				Action:  "encode",
			},
			expectedStatus: http.StatusOK,
			expectedResult: "hello%40world.com",
			expectError:    false,
		},
		{
			name: "invalid action",
			request: URLEncodeRequest{
				Content: "hello world",
				Action:  "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "invalid URL decode",
			request: URLEncodeRequest{
				Content: "hello%ZZ",
				Action:  "decode",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	executeURLTests(t, router, tests)
}

func TestHandler_JWTDecode(t *testing.T) {
	router := setupTestRouter()
	// #nosec G101 - test token only
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
		"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := getJWTHandlerTestCases(validToken)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeJWTDecodeTest(t, router, tt)
		})
	}
}

func getJWTHandlerTestCases(validToken string) []struct {
	name           string
	request        JWTDecodeRequest
	expectedStatus int
	expectError    bool
} {
	return []struct {
		name           string
		request        JWTDecodeRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "valid JWT token",
			request:        JWTDecodeRequest{Token: validToken},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "invalid JWT format",
			request:        JWTDecodeRequest{Token: "invalid.token"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "invalid base64 in header",
			request:        JWTDecodeRequest{Token: "invalid!!!.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"}, //nolint:lll
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}
}

func executeJWTDecodeTest(t *testing.T, router *gin.Engine, tt struct {
	name           string
	request        JWTDecodeRequest
	expectedStatus int
	expectError    bool
}) {
	body, _ := json.Marshal(tt.request)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/transform/jwt/decode", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, tt.expectedStatus, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	if tt.expectError {
		assert.False(t, response["success"].(bool))
		assert.NotNil(t, response["error"])
	} else {
		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		assert.False(t, data["signatureVerified"].(bool))
		assert.NotNil(t, data["header"])
		assert.NotNil(t, data["payload"])
	}
}

func TestHandler_Compress(t *testing.T) {
	router := setupTestRouter()
	tests := getCompressionHandlerTestCases()
	executeCompressionTests(t, router, tests)
}

// getCompressionHandlerTestCases returns test cases for compression handler testing.
func getCompressionHandlerTestCases() []struct {
	name           string
	request        CompressionRequest
	expectedStatus int
	expectError    bool
} {
	return []struct {
		name           string
		request        CompressionRequest
		expectedStatus int
		expectError    bool
	}{
		{
			name: "gzip compression",
			request: CompressionRequest{
				Content:   "Hello, World! This is a test string for compression.",
				Action:    "compress",
				Algorithm: "gzip",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "zlib compression",
			request: CompressionRequest{
				Content:   "Hello, World! This is a test string for compression.",
				Action:    "compress",
				Algorithm: "zlib",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "unsupported algorithm",
			request: CompressionRequest{
				Content:   "Hello, World!",
				Action:    "compress",
				Algorithm: "bzip2",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "invalid action",
			request: CompressionRequest{
				Content:   "Hello, World!",
				Action:    "invalid",
				Algorithm: "gzip",
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}
}

// executeCompressionTests executes compression handler tests.
func executeCompressionTests(t *testing.T, router *gin.Engine, tests []struct {
	name           string
	request        CompressionRequest
	expectedStatus int
	expectError    bool
}) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/transform/compress", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.False(t, response["success"].(bool))
				assert.NotNil(t, response["error"])
			} else {
				assert.True(t, response["success"].(bool))
				data := response["data"].(map[string]interface{})
				assert.NotEmpty(t, data["result"])
			}
		})
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	router := setupTestRouter()

	endpoints := []string{
		"/api/v1/transform/base64",
		"/api/v1/transform/url",
		"/api/v1/transform/jwt/decode",
		"/api/v1/transform/compress",
	}

	for _, endpoint := range endpoints {
		t.Run("invalid JSON for "+endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString("invalid json"))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.NotNil(t, response["error"])
		})
	}
}

// Generic helper function to execute transform tests.
func executeTransformTests(t *testing.T, router *gin.Engine, endpoint string, tests []struct {
	name           string
	request        interface{}
	expectedStatus int
	expectedResult string
	expectError    bool
}) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.False(t, response["success"].(bool))
				assert.NotNil(t, response["error"])
			} else {
				assert.True(t, response["success"].(bool))
				data := response["data"].(map[string]interface{})
				assert.Equal(t, tt.expectedResult, data["result"])
			}
		})
	}
}

// Helper function to execute Base64 transform tests.
func executeBase64Tests(t *testing.T, router *gin.Engine, tests []struct {
	name           string
	request        Base64Request
	expectedStatus int
	expectedResult string
	expectError    bool
}) {
	var genericTests []struct {
		name           string
		request        interface{}
		expectedStatus int
		expectedResult string
		expectError    bool
	}

	for _, test := range tests {
		genericTests = append(genericTests, struct {
			name           string
			request        interface{}
			expectedStatus int
			expectedResult string
			expectError    bool
		}{
			name:           test.name,
			request:        test.request,
			expectedStatus: test.expectedStatus,
			expectedResult: test.expectedResult,
			expectError:    test.expectError,
		})
	}

	executeTransformTests(t, router, "/api/v1/transform/base64", genericTests)
}

// Helper function to execute URL transform tests.
func executeURLTests(t *testing.T, router *gin.Engine, tests []struct {
	name           string
	request        URLEncodeRequest
	expectedStatus int
	expectedResult string
	expectError    bool
}) {
	var genericTests []struct {
		name           string
		request        interface{}
		expectedStatus int
		expectedResult string
		expectError    bool
	}

	for _, test := range tests {
		genericTests = append(genericTests, struct {
			name           string
			request        interface{}
			expectedStatus int
			expectedResult string
			expectError    bool
		}{
			name:           test.name,
			request:        test.request,
			expectedStatus: test.expectedStatus,
			expectedResult: test.expectedResult,
			expectError:    test.expectError,
		})
	}

	executeTransformTests(t, router, "/api/v1/transform/url", genericTests)
}
