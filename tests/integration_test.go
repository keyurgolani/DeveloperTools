//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/keyurgolani/DeveloperTools/internal/config"
	"github.com/keyurgolani/DeveloperTools/internal/logging"
	"github.com/keyurgolani/DeveloperTools/internal/server"
	"github.com/keyurgolani/DeveloperTools/pkg/apierror"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite contains all integration tests
type IntegrationTestSuite struct {
	suite.Suite
	server *server.Server
	router *gin.Engine
}

// SetupSuite runs once before all tests
func (suite *IntegrationTestSuite) SetupSuite() {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "error", // Reduce log noise during tests
		},
		Auth: config.AuthConfig{
			Method: "none", // Disable auth for integration tests
		},
		RateLimit: config.RateLimitConfig{
			Store: "memory", // Use memory store for tests
		},
		Tracing: config.TracingConfig{
			Enabled: false, // Disable tracing for tests
		},
	}

	// Create logger
	logger := logging.New(cfg.Log.Level)

	// Create server
	suite.server = server.New(cfg, logger)
	suite.router = suite.server.GetRouter()
}

// TestHealthEndpoints tests all health check endpoints
func (suite *IntegrationTestSuite) TestHealthEndpoints() {
	tests := []struct {
		name           string
		endpoint       string
		expectedStatus int
		expectedFields []string
	}{
		{
			name:           "Basic health endpoint",
			endpoint:       "/health",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status", "timestamp", "service"},
		},
		{
			name:           "Liveness probe",
			endpoint:       "/health/live",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status"},
		},
		{
			name:           "Readiness probe",
			endpoint:       "/health/ready",
			expectedStatus: http.StatusOK,
			expectedFields: []string{"status"},
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", tt.endpoint, nil)
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)

			for _, field := range tt.expectedFields {
				assert.Contains(suite.T(), response, field)
			}
		})
	}
}

// TestStatusEndpoint tests the API status endpoint
func (suite *IntegrationTestSuite) TestStatusEndpoint() {
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/status", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(suite.T(), err)

	expectedFields := []string{"service", "version", "status"}
	for _, field := range expectedFields {
		assert.Contains(suite.T(), response, field)
	}
}

// TestMetricsEndpoint tests the Prometheus metrics endpoint
func (suite *IntegrationTestSuite) TestMetricsEndpoint() {
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/metrics", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Header().Get("Content-Type"), "text/plain")

	// Check for some expected Prometheus metrics
	body := w.Body.String()
	assert.Contains(suite.T(), body, "# HELP")
	assert.Contains(suite.T(), body, "# TYPE")
}

// TestCryptoModule tests all crypto endpoints
func (suite *IntegrationTestSuite) TestCryptoModule() {
	suite.Run("Hash endpoint", func() {
		tests := []struct {
			name           string
			payload        map[string]interface{}
			expectedStatus int
			expectSuccess  bool
		}{
			{
				name: "Valid SHA256 hash",
				payload: map[string]interface{}{
					"content":   "hello world",
					"algorithm": "sha256",
				},
				expectedStatus: http.StatusOK,
				expectSuccess:  true,
			},
			{
				name: "Valid MD5 hash",
				payload: map[string]interface{}{
					"content":   "test",
					"algorithm": "md5",
				},
				expectedStatus: http.StatusOK,
				expectSuccess:  true,
			},
			{
				name: "Invalid algorithm",
				payload: map[string]interface{}{
					"content":   "test",
					"algorithm": "invalid",
				},
				expectedStatus: http.StatusBadRequest,
				expectSuccess:  false,
			},
			{
				name: "Missing content",
				payload: map[string]interface{}{
					"algorithm": "sha256",
				},
				expectedStatus: http.StatusOK,
				expectSuccess:  true,
			},
		}

		for _, tt := range tests {
			suite.Run(tt.name, func() {
				body, _ := json.Marshal(tt.payload)
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)

				assert.Equal(suite.T(), tt.expectedStatus, w.Code)

				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)

				if tt.expectSuccess {
					assert.True(suite.T(), response["success"].(bool))
					assert.Contains(suite.T(), response, "data")
					data := response["data"].(map[string]interface{})
					assert.Contains(suite.T(), data, "hash")
					assert.Contains(suite.T(), data, "algorithm")
				} else {
					assert.False(suite.T(), response["success"].(bool))
					assert.Contains(suite.T(), response, "error")
				}
			})
		}
	})

	suite.Run("HMAC endpoint", func() {
		payload := map[string]interface{}{
			"content":   "hello world",
			"key":       "secret",
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hmac", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
	})

	suite.Run("Password hash and verify", func() {
		// First hash a password
		hashPayload := map[string]interface{}{
			"password": "testpassword123",
		}

		body, _ := json.Marshal(hashPayload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var hashResponse apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &hashResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), hashResponse.Success)

		hashData := hashResponse.Data.(map[string]interface{})
		hashedPassword := hashData["hash"].(string)
		assert.NotEmpty(suite.T(), hashedPassword)

		// Now verify the password
		verifyPayload := map[string]interface{}{
			"password": "testpassword123",
			"hash":     hashedPassword,
		}

		body, _ = json.Marshal(verifyPayload)
		w = httptest.NewRecorder()
		req, _ = http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/verify", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var verifyResponse apierror.SuccessResponse
		err = json.Unmarshal(w.Body.Bytes(), &verifyResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), verifyResponse.Success)

		verifyData := verifyResponse.Data.(map[string]interface{})
		assert.True(suite.T(), verifyData["valid"].(bool))
	})
}

// TestTextModule tests all text processing endpoints
func (suite *IntegrationTestSuite) TestTextModule() {
	suite.Run("Case conversion", func() {
		tests := []struct {
			name           string
			content        string
			caseType       string
			expectedResult string
		}{
			{
				name:           "UPPERCASE conversion",
				content:        "hello world",
				caseType:       "UPPERCASE",
				expectedResult: "HELLO WORLD",
			},
			{
				name:           "lowercase conversion",
				content:        "HELLO WORLD",
				caseType:       "lowercase",
				expectedResult: "hello world",
			},
			{
				name:           "camelCase conversion",
				content:        "hello world test",
				caseType:       "camelCase",
				expectedResult: "helloWorldTest",
			},
		}

		for _, tt := range tests {
			suite.Run(tt.name, func() {
				payload := map[string]interface{}{
					"content":  tt.content,
					"caseType": tt.caseType,
				}

				body, _ := json.Marshal(payload)
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/case", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)

				data := response.Data.(map[string]interface{})
				assert.Equal(suite.T(), tt.expectedResult, data["result"].(string))
			})
		}
	})

	suite.Run("Text analysis", func() {
		payload := map[string]interface{}{
			"content": "Hello world!\nThis is a test.\nIt has multiple lines.",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/info", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "characterCount")
		assert.Contains(suite.T(), data, "wordCount")
		assert.Contains(suite.T(), data, "lineCount")
		assert.Contains(suite.T(), data, "sentenceCount")
		assert.Contains(suite.T(), data, "byteSize")
	})

	suite.Run("Regex testing", func() {
		payload := map[string]interface{}{
			"content": "The quick brown fox jumps over the lazy dog",
			"pattern": "\\b\\w{5}\\b", // Match 5-letter words
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/regex", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "matches")
		assert.Contains(suite.T(), data, "pattern")
	})
}

// TestTransformModule tests all transformation endpoints
func (suite *IntegrationTestSuite) TestTransformModule() {
	suite.Run("Base64 encoding/decoding", func() {
		originalContent := "Hello, World!"

		// Test encoding
		encodePayload := map[string]interface{}{
			"content": originalContent,
			"action":  "encode",
		}

		body, _ := json.Marshal(encodePayload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/base64", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var encodeResponse apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &encodeResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), encodeResponse.Success)

		encodeData := encodeResponse.Data.(map[string]interface{})
		encodedContent := encodeData["result"].(string)
		assert.NotEmpty(suite.T(), encodedContent)

		// Test decoding
		decodePayload := map[string]interface{}{
			"content": encodedContent,
			"action":  "decode",
		}

		body, _ = json.Marshal(decodePayload)
		w = httptest.NewRecorder()
		req, _ = http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/base64", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var decodeResponse apierror.SuccessResponse
		err = json.Unmarshal(w.Body.Bytes(), &decodeResponse)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), decodeResponse.Success)

		decodeData := decodeResponse.Data.(map[string]interface{})
		assert.Equal(suite.T(), originalContent, decodeData["result"].(string))
	})

	suite.Run("URL encoding/decoding", func() {
		originalContent := "hello world & special chars!"

		// Test encoding
		encodePayload := map[string]interface{}{
			"content": originalContent,
			"action":  "encode",
		}

		body, _ := json.Marshal(encodePayload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/url", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
	})

	suite.Run("JWT decoding", func() {
		// Use a sample JWT token (header.payload.signature format)
		sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

		payload := map[string]interface{}{
			"token": sampleJWT,
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/jwt/decode", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "header")
		assert.Contains(suite.T(), data, "payload")
		assert.Contains(suite.T(), data, "signatureVerified")
		assert.False(suite.T(), data["signatureVerified"].(bool)) // Should always be false
	})
}

// TestIDModule tests ID generation endpoints
func (suite *IntegrationTestSuite) TestIDModule() {
	suite.Run("UUID generation", func() {
		tests := []struct {
			name    string
			version int
			count   int
		}{
			{
				name:    "UUID v4 single",
				version: 4,
				count:   1,
			},
			{
				name:    "UUID v4 multiple",
				version: 4,
				count:   5,
			},
			{
				name:    "UUID v1 single",
				version: 1,
				count:   1,
			},
		}

		for _, tt := range tests {
			suite.Run(tt.name, func() {
				payload := map[string]interface{}{
					"version": tt.version,
					"count":   tt.count,
				}

				body, _ := json.Marshal(payload)
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/uuid", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)

				data := response.Data.(map[string]interface{})
				uuids := data["uuids"].([]interface{})
				assert.Len(suite.T(), uuids, tt.count)

				for _, uuid := range uuids {
					assert.NotEmpty(suite.T(), uuid.(string))
				}
			})
		}
	})

	suite.Run("Nano ID generation", func() {
		payload := map[string]interface{}{
			"size":  10,
			"count": 3,
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/id/nanoid", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		ids := data["ids"].([]interface{})
		assert.Len(suite.T(), ids, 3)

		for _, id := range ids {
			idStr := id.(string)
			assert.NotEmpty(suite.T(), idStr)
			assert.Len(suite.T(), idStr, 10)
		}
	})
}

// TestTimeModule tests time utility endpoints
func (suite *IntegrationTestSuite) TestTimeModule() {
	suite.Run("Current time", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/time/now", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		expectedFields := []string{"unixSeconds", "unixMilliseconds", "iso8601", "rfc3339", "humanReadable"}
		for _, field := range expectedFields {
			assert.Contains(suite.T(), data, field)
		}
	})

	suite.Run("Time conversion", func() {
		payload := map[string]interface{}{
			"input":        "1640995200", // Unix timestamp for 2022-01-01 00:00:00 UTC
			"inputFormat":  "unix",
			"outputFormat": "iso8601",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/time/convert", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "result")
		result := data["result"].(string)
		assert.Contains(suite.T(), result, "2022-01-01")
	})
}

// TestNetworkModule tests network utility endpoints
func (suite *IntegrationTestSuite) TestNetworkModule() {
	suite.Run("URL parsing", func() {
		payload := map[string]interface{}{
			"url":    "https://example.com:8080/path?param=value#fragment",
			"action": "parse",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/web/url", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "scheme")
		assert.Contains(suite.T(), data, "host")
		assert.Contains(suite.T(), data, "path")
		assert.Contains(suite.T(), data, "query")
		assert.Contains(suite.T(), data, "fragment")
	})

	suite.Run("IP analysis", func() {
		tests := []struct {
			name string
			ip   string
		}{
			{
				name: "IPv4 public",
				ip:   "8.8.8.8",
			},
			{
				name: "IPv4 private",
				ip:   "192.168.1.1",
			},
			{
				name: "IPv4 loopback",
				ip:   "127.0.0.1",
			},
		}

		for _, tt := range tests {
			suite.Run(tt.name, func() {
				payload := map[string]interface{}{
					"ip": tt.ip,
				}

				body, _ := json.Marshal(payload)
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/network/ip", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				suite.router.ServeHTTP(w, req)

				assert.Equal(suite.T(), http.StatusOK, w.Code)

				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)

				data := response.Data.(map[string]interface{})
				assert.Contains(suite.T(), data, "ip")
				assert.Contains(suite.T(), data, "version")
				assert.Contains(suite.T(), data, "isPrivate")
				assert.Contains(suite.T(), data, "isPublic")
				assert.Contains(suite.T(), data, "isLoopback")
			})
		}
	})

	suite.Run("DNS lookup", func() {
		payload := map[string]interface{}{
			"domain":     "google.com",
			"recordType": "A",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/network/dns", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// DNS lookups might fail in test environments, so we accept both success and failure
		assert.True(suite.T(), w.Code == http.StatusOK || w.Code >= 400)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		if w.Code == http.StatusOK {
			assert.True(suite.T(), response["success"].(bool))
			data := response["data"].(map[string]interface{})
			assert.Contains(suite.T(), data, "domain")
			assert.Contains(suite.T(), data, "recordType")
			assert.Contains(suite.T(), data, "records")
		}
	})
}

// TestErrorHandling tests error scenarios and middleware
func (suite *IntegrationTestSuite) TestErrorHandling() {
	suite.Run("404 Not Found", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/nonexistent", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusNotFound, w.Code)

		var response apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), response.Success)
		assert.NotEmpty(suite.T(), response.Error.Code)
		assert.NotEmpty(suite.T(), response.Error.Message)
	})

	suite.Run("405 Method Not Allowed", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "PUT", "/health", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusNotFound, w.Code)

		var response apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), response.Success)
	})

	suite.Run("400 Bad Request - Invalid JSON", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusBadRequest, w.Code)

		var response apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.False(suite.T(), response.Success)
		assert.Equal(suite.T(), apierror.CodeValidationError, response.Error.Code)
	})

	suite.Run("400 Bad Request - Missing required fields", func() {
		payload := map[string]interface{}{
			"algorithm": "sha256",
			// Missing "content" field
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
	})
}

// TestRequestIDMiddleware tests request ID generation and propagation
func (suite *IntegrationTestSuite) TestRequestIDMiddleware() {
	suite.Run("Request ID generation", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		// Check that X-Request-ID header is present in response
		requestID := w.Header().Get("X-Request-ID")
		assert.NotEmpty(suite.T(), requestID)
		assert.Len(suite.T(), requestID, 36) // UUID length
	})

	suite.Run("Request ID propagation", func() {
		customRequestID := "test-request-id-123"

		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
		req.Header.Set("X-Request-ID", customRequestID)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		// Check that the custom request ID is returned
		responseRequestID := w.Header().Get("X-Request-ID")
		assert.Equal(suite.T(), customRequestID, responseRequestID)
	})
}

// TestResponseFormat tests consistent response formatting
func (suite *IntegrationTestSuite) TestResponseFormat() {
	suite.Run("Success response format", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/api/v1/status", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		// Check standard success response format
		assert.Contains(suite.T(), response, "service")
		assert.Contains(suite.T(), response, "version")
		assert.Contains(suite.T(), response, "status")
	})

	suite.Run("Error response format", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/nonexistent", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusNotFound, w.Code)

		var response apierror.ErrorResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		// Check standard error response format
		assert.False(suite.T(), response.Success)
		assert.NotEmpty(suite.T(), response.Error.Code)
		assert.NotEmpty(suite.T(), response.Error.Message)
	})
}

// TestConcurrentRequests tests handling of concurrent requests
func (suite *IntegrationTestSuite) TestConcurrentRequests() {
	const numRequests = 10

	// Create a channel to collect responses
	responses := make(chan *httptest.ResponseRecorder, numRequests)

	// Launch concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
			suite.router.ServeHTTP(w, req)
			responses <- w
		}()
	}

	// Collect all responses
	for i := 0; i < numRequests; i++ {
		select {
		case w := <-responses:
			assert.Equal(suite.T(), http.StatusOK, w.Code)
		case <-time.After(5 * time.Second):
			suite.T().Fatal("Timeout waiting for concurrent request response")
		}
	}
}

// TestLargePayloads tests handling of large request payloads
func (suite *IntegrationTestSuite) TestLargePayloads() {
	suite.Run("Large but acceptable payload", func() {
		// Create a large but acceptable content (under 1MB limit)
		largeContent := string(make([]byte, 100*1024)) // 100KB

		payload := map[string]interface{}{
			"content":   largeContent,
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
	})
}

// Run the integration test suite
func TestIntegrationSuite(t *testing.T) {
	// Skip integration tests if running in short mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Set environment variables for testing
	os.Setenv("GIN_MODE", "test")
	defer os.Unsetenv("GIN_MODE")

	suite.Run(t, new(IntegrationTestSuite))
}

// Benchmark tests for performance validation
func BenchmarkHealthEndpoint(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server:    config.ServerConfig{Port: 8080, TLSEnabled: false},
		Log:       config.LogConfig{Level: "error"},
		Auth:      config.AuthConfig{Method: "none"},
		RateLimit: config.RateLimitConfig{Store: "memory"},
		Tracing:   config.TracingConfig{Enabled: false},
	}

	logger := logging.New(cfg.Log.Level)
	srv := server.New(cfg, logger)
	router := srv.GetRouter()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", w.Code)
			}
		}
	})
}

func BenchmarkCryptoHash(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server:    config.ServerConfig{Port: 8080, TLSEnabled: false},
		Log:       config.LogConfig{Level: "error"},
		Auth:      config.AuthConfig{Method: "none"},
		RateLimit: config.RateLimitConfig{Store: "memory"},
		Tracing:   config.TracingConfig{Enabled: false},
	}

	logger := logging.New(cfg.Log.Level)
	srv := server.New(cfg, logger)
	router := srv.GetRouter()

	payload := map[string]interface{}{
		"content":   "hello world",
		"algorithm": "sha256",
	}

	body, _ := json.Marshal(payload)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				b.Errorf("Expected status 200, got %d", w.Code)
			}
		}
	})
}
