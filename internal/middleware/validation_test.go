package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyurgolani/DeveloperTools/internal/middleware"
)

func TestValidationMiddleware_LimitRequestSize(t *testing.T) {
	logger := createTestLogger()
	config := &middleware.ValidationConfig{
		MaxBodySize: 100, // 100 bytes for testing
	}

	validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
	require.NoError(t, err)

	router := gin.New()
	router.Use(validationMiddleware.LimitRequestSize())
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("Request within size limit", func(t *testing.T) {
		body := strings.Repeat("a", 50) // 50 bytes
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Request exceeding size limit", func(t *testing.T) {
		body := strings.Repeat("a", 200) // 200 bytes, exceeds 100 byte limit
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
		assert.Contains(t, w.Body.String(), "REQUEST_TOO_LARGE")
		assert.Contains(t, w.Body.String(), "100 bytes")
	})
}

func TestValidationMiddleware_ValidateURL(t *testing.T) {
	middleware := setupValidationMiddleware(t)
	tests := getValidateURLTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeValidateURLTest(t, middleware, tt)
		})
	}
}

func setupValidationMiddleware(t *testing.T) *middleware.ValidationMiddleware {
	logger := createTestLogger()
	config := middleware.DefaultValidationConfig()

	validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
	require.NoError(t, err)
	return validationMiddleware
}

func getValidURLTestCases() []struct {
	name        string
	url         string
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid HTTP URL",
			url:         "http://example.com/path",
			expectError: false,
		},
		{
			name:        "Valid HTTPS URL",
			url:         "https://example.com/path",
			expectError: false,
		},
	}
}

func getInvalidURLTestCases() []struct {
	name        string
	url         string
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty URL",
			url:         "",
			expectError: true,
			errorMsg:    "URL cannot be empty",
		},
		{
			name:        "Invalid URL format",
			url:         "not-a-url",
			expectError: true,
			errorMsg:    "scheme  is not allowed",
		},
		{
			name:        "Disallowed scheme",
			url:         "ftp://example.com/file",
			expectError: true,
			errorMsg:    "scheme ftp is not allowed",
		},
	}
}

func getSSRFProtectionTestCases() []struct {
	name        string
	url         string
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Localhost URL",
			url:         "http://localhost:8080/admin",
			expectError: true,
			errorMsg:    "loopback IP addresses are not allowed",
		},
		{
			name:        "Private IP URL",
			url:         "http://192.168.1.1/internal",
			expectError: true,
			errorMsg:    "private IP addresses are not allowed",
		},
		{
			name:        "AWS metadata URL",
			url:         "http://169.254.169.254/latest/meta-data/",
			expectError: true,
			errorMsg:    "link-local IP addresses are not allowed",
		},
		{
			name:        "Link-local URL",
			url:         "http://169.254.1.1/test",
			expectError: true,
			errorMsg:    "link-local IP addresses are not allowed",
		},
	}
}

func getValidateURLTestCases() []struct {
	name        string
	url         string
	expectError bool
	errorMsg    string
} {
	var testCases []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}

	testCases = append(testCases, getValidURLTestCases()...)
	testCases = append(testCases, getInvalidURLTestCases()...)
	testCases = append(testCases, getSSRFProtectionTestCases()...)

	return testCases
}

func executeValidateURLTest(t *testing.T, validationMiddleware *middleware.ValidationMiddleware, tt struct {
	name        string
	url         string
	expectError bool
	errorMsg    string
},
) {
	err := validationMiddleware.ValidateURL(tt.url)

	if tt.expectError {
		assert.Error(t, err)
		if tt.errorMsg != "" {
			assert.Contains(t, err.Error(), tt.errorMsg)
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestValidationMiddleware_ValidateURL_CustomConfig(t *testing.T) {
	logger := createTestLogger()
	config := &middleware.ValidationConfig{
		MaxBodySize:       1024,
		AllowedSchemes:    []string{"http", "https", "ftp"},
		BlockedDomains:    []string{"evil.com", "malicious.org"},
		AllowPrivateIPs:   true,
		AllowLoopbackIPs:  false,
		AllowLinkLocalIPs: false,
	}

	validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "FTP allowed with custom config",
			url:         "ftp://example.com/file",
			expectError: false,
		},
		{
			name:        "Private IP allowed with custom config",
			url:         "http://192.168.1.1/test",
			expectError: false,
		},
		{
			name:        "Blocked domain",
			url:         "http://evil.com/payload",
			expectError: true,
			errorMsg:    "domain evil.com is blocked",
		},
		{
			name:        "Localhost still blocked",
			url:         "http://localhost/test",
			expectError: true,
			errorMsg:    "loopback IP addresses are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validationMiddleware.ValidateURL(tt.url)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationMiddleware_ValidateURL_BlockedCIDRs(t *testing.T) {
	logger := createTestLogger()
	config := &middleware.ValidationConfig{
		MaxBodySize:    1024,
		AllowedSchemes: []string{"http", "https"},
		BlockedCIDRs:   []string{"203.0.113.0/24", "198.51.100.0/24"},
	}

	validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "IP in blocked CIDR",
			url:         "http://203.0.113.50/test",
			expectError: true,
		},
		{
			name:        "IP not in blocked CIDR",
			url:         "http://203.0.114.50/test",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validationMiddleware.ValidateURL(tt.url)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "blocked network")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationMiddleware_ValidateInput(t *testing.T) {
	middleware := setupValidationMiddlewareForInput(t)
	tests := getValidateInputTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeValidateInputTest(t, middleware, tt)
		})
	}
}

func setupValidationMiddlewareForInput(t *testing.T) *middleware.ValidationMiddleware {
	logger := createTestLogger()
	validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
	require.NoError(t, err)
	return validationMiddleware
}

func getValidInputTestCases() []struct {
	name        string
	input       string
	maxLength   int
	allowEmpty  bool
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		input       string
		maxLength   int
		allowEmpty  bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid input",
			input:       "Hello, World!",
			maxLength:   100,
			allowEmpty:  false,
			expectError: false,
		},
		{
			name:        "Empty input allowed",
			input:       "",
			maxLength:   100,
			allowEmpty:  true,
			expectError: false,
		},
		{
			name:        "Input with acceptable control characters",
			input:       "Line 1\nLine 2\tTabbed",
			maxLength:   100,
			allowEmpty:  false,
			expectError: false,
		},
	}
}

func getInvalidInputTestCases() []struct {
	name        string
	input       string
	maxLength   int
	allowEmpty  bool
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		input       string
		maxLength   int
		allowEmpty  bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty input not allowed",
			input:       "",
			maxLength:   100,
			allowEmpty:  false,
			expectError: true,
			errorMsg:    "input cannot be empty",
		},
		{
			name:        "Input too long",
			input:       strings.Repeat("a", 200),
			maxLength:   100,
			allowEmpty:  false,
			expectError: true,
			errorMsg:    "input too long",
		},
		{
			name:        "Input with null bytes",
			input:       "Hello\x00World",
			maxLength:   100,
			allowEmpty:  false,
			expectError: true,
			errorMsg:    "input contains null bytes",
		},
		{
			name:        "Input with many control characters",
			input:       "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A", // 10 control chars
			maxLength:   100,
			allowEmpty:  false,
			expectError: true,
			errorMsg:    "too many control characters",
		},
	}
}

func getValidateInputTestCases() []struct {
	name        string
	input       string
	maxLength   int
	allowEmpty  bool
	expectError bool
	errorMsg    string
} {
	var testCases []struct {
		name        string
		input       string
		maxLength   int
		allowEmpty  bool
		expectError bool
		errorMsg    string
	}

	testCases = append(testCases, getValidInputTestCases()...)
	testCases = append(testCases, getInvalidInputTestCases()...)

	return testCases
}

func executeValidateInputTest(t *testing.T, middleware *middleware.ValidationMiddleware, tt struct {
	name        string
	input       string
	maxLength   int
	allowEmpty  bool
	expectError bool
	errorMsg    string
},
) {
	err := middleware.ValidateInput(tt.input, tt.maxLength, tt.allowEmpty)

	if tt.expectError {
		assert.Error(t, err)
		if tt.errorMsg != "" {
			assert.Contains(t, err.Error(), tt.errorMsg)
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestValidationMiddleware_ValidateRegex(t *testing.T) {
	logger := createTestLogger()
	validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		pattern     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid simple pattern",
			pattern:     "^[a-zA-Z0-9]+$",
			expectError: false,
		},
		{
			name:        "Valid complex pattern",
			pattern:     `^\d{3}-\d{2}-\d{4}$`,
			expectError: false,
		},
		{
			name:        "Empty pattern",
			pattern:     "",
			expectError: true,
			errorMsg:    "regex pattern cannot be empty",
		},
		{
			name:        "Pattern too long",
			pattern:     strings.Repeat("a", 1001),
			expectError: true,
			errorMsg:    "regex pattern too long",
		},
		{
			name:        "Invalid regex syntax",
			pattern:     "[invalid",
			expectError: true,
			errorMsg:    "invalid regex pattern",
		},
		{
			name:        "Potentially dangerous pattern with comments",
			pattern:     "(?#comment)test",
			expectError: true,
			errorMsg:    "invalid regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validationMiddleware.ValidateRegex(tt.pattern)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationMiddleware_ValidateJSON(t *testing.T) {
	middleware := setupValidationMiddlewareForJSON(t)
	tests := getValidateJSONTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeValidateJSONTest(t, middleware, tt)
		})
	}
}

func setupValidationMiddlewareForJSON(t *testing.T) *middleware.ValidationMiddleware {
	logger := createTestLogger()
	validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
	require.NoError(t, err)
	return validationMiddleware
}

func getValidateJSONTestCases() []struct {
	name        string
	input       string
	maxSize     int
	expectError bool
	errorMsg    string
} {
	return []struct {
		name        string
		input       string
		maxSize     int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid JSON object",
			input:       `{"key": "value", "number": 123}`,
			maxSize:     1000,
			expectError: false,
		},
		{
			name:        "Valid JSON array",
			input:       `[1, 2, 3, "test"]`,
			maxSize:     1000,
			expectError: false,
		},
		{
			name:        "JSON too large",
			input:       `{"key": "value"}`,
			maxSize:     10,
			expectError: true,
			errorMsg:    "JSON input too large",
		},
		{
			name:        "Not JSON format",
			input:       "not json",
			maxSize:     1000,
			expectError: true,
			errorMsg:    "does not appear to be valid JSON",
		},
		{
			name:        "Unbalanced braces",
			input:       `{"key": "value"`,
			maxSize:     1000,
			expectError: true,
			errorMsg:    "unbalanced braces or brackets",
		},
		{
			name:        "Unbalanced brackets",
			input:       `[1, 2, 3`,
			maxSize:     1000,
			expectError: true,
			errorMsg:    "unbalanced braces or brackets",
		},
		{
			name:        "JSON with escaped quotes",
			input:       `{"message": "He said \"Hello\""}`,
			maxSize:     1000,
			expectError: false,
		},
	}
}

func executeValidateJSONTest(t *testing.T, middleware *middleware.ValidationMiddleware, tt struct {
	name        string
	input       string
	maxSize     int
	expectError bool
	errorMsg    string
},
) {
	err := middleware.ValidateJSON(tt.input, tt.maxSize)

	if tt.expectError {
		assert.Error(t, err)
		if tt.errorMsg != "" {
			assert.Contains(t, err.Error(), tt.errorMsg)
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestValidationMiddleware_SanitizeInput(t *testing.T) {
	logger := createTestLogger()
	validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
	require.NoError(t, err)

	router := gin.New()
	router.Use(validationMiddleware.SanitizeInput())
	router.GET("/test", func(c *gin.Context) {
		param := c.Query("param")
		c.JSON(http.StatusOK, gin.H{"param": param})
	})

	t.Run("Sanitize query parameters", func(t *testing.T) {
		// Create a request with valid URL
		req := httptest.NewRequest("GET", "/test?param=HelloWorld", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// The sanitization is tested separately in TestValidationMiddleware_SanitizeString
	})
}

func TestNewValidationMiddleware_InvalidConfig(t *testing.T) {
	logger := createTestLogger()

	t.Run("Invalid CIDR", func(t *testing.T) {
		config := &middleware.ValidationConfig{
			BlockedCIDRs: []string{"invalid-cidr"},
		}

		validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CIDR")
		assert.Nil(t, validationMiddleware)
	})

	t.Run("Nil config uses defaults", func(t *testing.T) {
		validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
		assert.NoError(t, err)
		assert.NotNil(t, validationMiddleware)
		// Note: Cannot test internal config values as they are unexported
	})
}

func TestSSRFProtection_IntegrationTest(t *testing.T) {
	logger := createTestLogger()
	validationMiddleware, err := middleware.NewValidationMiddleware(nil, logger)
	require.NoError(t, err)

	// Test various SSRF attack vectors
	ssrfURLs := []string{
		"http://127.0.0.1:8080/admin",
		"http://localhost/admin",
		"http://192.168.1.1/internal",
		"http://10.0.0.1/private",
		"http://172.16.0.1/internal",
		"http://169.254.169.254/latest/meta-data/", // AWS metadata
		"http://metadata.google.internal/",         // GCP metadata (would fail DNS)
		"http://[::1]/admin",                       // IPv6 loopback
		"http://0.0.0.0/test",                      // This network
		"http://255.255.255.255/broadcast",         // Broadcast
	}

	for _, url := range ssrfURLs {
		t.Run("Block "+url, func(t *testing.T) {
			err := validationMiddleware.ValidateURL(url)
			assert.Error(t, err, "Should block SSRF attempt: %s", url)
		})
	}
}

func TestInputValidation_IntegrationTest(t *testing.T) {
	logger := createTestLogger()
	config := &middleware.ValidationConfig{
		MaxBodySize: 1024,
	}

	validationMiddleware, err := middleware.NewValidationMiddleware(config, logger)
	require.NoError(t, err)

	router := gin.New()
	router.Use(validationMiddleware.LimitRequestSize())
	router.POST("/test", func(c *gin.Context) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(c.Request.Body)
		c.JSON(http.StatusOK, gin.H{"received": body.Len()})
	})

	t.Run("Large payload attack", func(t *testing.T) {
		// Try to send a payload larger than the limit
		largePayload := strings.Repeat("A", 2048) // 2KB payload
		req := httptest.NewRequest("POST", "/test", strings.NewReader(largePayload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
		assert.Contains(t, w.Body.String(), "REQUEST_TOO_LARGE")
	})
}
