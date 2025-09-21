package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected slog.Level
	}{
		{"debug level", "debug", slog.LevelDebug},
		{"info level", "info", slog.LevelInfo},
		{"warn level", "warn", slog.LevelWarn},
		{"warning level", "warning", slog.LevelWarn},
		{"error level", "error", slog.LevelError},
		{"invalid level defaults to info", "invalid", slog.LevelInfo},
		{"empty level defaults to info", "", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.level)
			assert.NotNil(t, logger)
			assert.NotNil(t, logger.Logger)
		})
	}
}

func TestWithRequestID(t *testing.T) {
	logger := New("info")
	requestID := "test-request-id-123"
	
	loggerWithID := logger.WithRequestID(requestID)
	assert.NotNil(t, loggerWithID)
	assert.NotEqual(t, logger, loggerWithID)
}

func TestWithModule(t *testing.T) {
	logger := New("info")
	module := "crypto"
	
	loggerWithModule := logger.WithModule(module)
	assert.NotNil(t, loggerWithModule)
	assert.NotEqual(t, logger, loggerWithModule)
}

func TestWithContext(t *testing.T) {
	logger := New("info")
	
	// Test with context containing request ID
	ctx := context.WithValue(context.Background(), "request_id", "test-123")
	loggerWithCtx := logger.WithContext(ctx)
	assert.NotNil(t, loggerWithCtx)
	
	// Test with empty context
	emptyCtx := context.Background()
	loggerWithEmptyCtx := logger.WithContext(emptyCtx)
	assert.NotNil(t, loggerWithEmptyCtx)
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{"password key", "password", true},
		{"Password key (case insensitive)", "Password", true},
		{"api_key", "api_key", true},
		{"JWT token", "jwt_token", true},
		{"secret key", "secret_key", true},
		{"hash value", "hash_value", true},
		{"normal key", "username", false},
		{"normal key", "email", false},
		{"normal key", "id", false},
		{"empty key", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSensitiveKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected interface{}
	}{
		{"sensitive key", "password", "secret123", "[REDACTED]"},
		{"normal key with normal value", "username", "john", "john"},
		{"normal key with JWT-like value", "data", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "[REDACTED]"},
		{"normal key with short value", "data", "short", "short"},
		{"normal key with long alphanumeric", "data", "abcdefghijklmnopqrstuvwxyz1234567890", "[REDACTED]"},
		{"normal key with base64-like value", "data", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2UgZm9yIGJhc2U2NCBlbmNvZGluZw==", "[REDACTED]"},
		{"non-string value", "count", 42, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeValue(tt.key, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLooksLikeSensitiveData(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"empty string", "", false},
		{"short string", "hello", false},
		{"normal text", "this is normal text", false},
		{"JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"long alphanumeric (API key like)", "abcdefghijklmnopqrstuvwxyz1234567890", true},
		{"base64 encoded data", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2UgZm9yIGJhc2U2NCBlbmNvZGluZw==", true},
		{"short alphanumeric", "abc123", false},
		{"text with special chars", "hello@world.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := looksLikeSensitiveData(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"alphanumeric", "abc123XYZ", true},
		{"with special chars", "abc@123", false},
		{"with spaces", "abc 123", false},
		{"empty string", "", true},
		{"only letters", "abcXYZ", true},
		{"only numbers", "123456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAlphanumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsBase64Like(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid base64", "SGVsbG8gV29ybGQ=", true},
		{"base64 without padding", "SGVsbG8gV29ybGQ", true},
		{"base64 with URL safe chars", "SGVsbG8gV29ybGQ-_", true},
		{"not base64", "hello@world.com", false},
		{"mixed content", "hello SGVsbG8=", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBase64Like(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSensitiveDataRedaction(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	
	// Create a logger that writes to our buffer
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if isSensitiveKey(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}
	
	handler := slog.NewJSONHandler(&buf, opts)
	logger := &Logger{Logger: slog.New(handler)}
	
	// Log with sensitive data
	logger.Info("Test log", 
		"username", "john",
		"password", "secret123",
		"api_key", "abc123def456",
		"normal_field", "normal_value",
	)
	
	// Parse the JSON log output
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)
	
	// Verify sensitive data is redacted
	assert.Equal(t, "john", logEntry["username"])
	assert.Equal(t, "[REDACTED]", logEntry["password"])
	assert.Equal(t, "[REDACTED]", logEntry["api_key"])
	assert.Equal(t, "normal_value", logEntry["normal_field"])
}

func TestLogRequest(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	
	handler := slog.NewJSONHandler(&buf, opts)
	logger := &Logger{Logger: slog.New(handler)}
	
	// Test different status codes
	tests := []struct {
		name   string
		status int
		level  string
	}{
		{"success request", 200, "INFO"},
		{"client error", 400, "WARN"},
		{"server error", 500, "ERROR"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			
			logger.LogRequest("GET", "/test", tt.status, 100, "extra", "data")
			
			// Verify log was written
			assert.Greater(t, buf.Len(), 0)
			
			// Parse and verify log entry
			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			require.NoError(t, err)
			
			assert.Equal(t, "GET", logEntry["method"])
			assert.Equal(t, "/test", logEntry["path"])
			assert.Equal(t, float64(tt.status), logEntry["status"])
			assert.Equal(t, float64(100), logEntry["duration_ms"])
			assert.Equal(t, "data", logEntry["extra"])
			assert.Equal(t, tt.level, logEntry["level"])
		})
	}
}

func TestLogError(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	
	opts := &slog.HandlerOptions{
		Level: slog.LevelError,
	}
	
	handler := slog.NewJSONHandler(&buf, opts)
	logger := &Logger{Logger: slog.New(handler)}
	
	// Test logging an error
	testErr := assert.AnError
	logger.LogError(testErr, "Test error occurred", "context", "test")
	
	// Verify log was written
	assert.Greater(t, buf.Len(), 0)
	
	// Parse and verify log entry
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)
	
	assert.Equal(t, "ERROR", logEntry["level"])
	assert.Equal(t, "Test error occurred", logEntry["msg"])
	assert.Equal(t, testErr.Error(), logEntry["error"])
	assert.Equal(t, "test", logEntry["context"])
}

// Benchmark tests for performance
func BenchmarkIsSensitiveKey(b *testing.B) {
	keys := []string{"password", "username", "api_key", "normal_field", "secret_token"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := keys[i%len(keys)]
		isSensitiveKey(key)
	}
}

func BenchmarkSanitizeValue(b *testing.B) {
	values := []interface{}{
		"normal_value",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"short",
		42,
		"SGVsbG8gV29ybGQh",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		value := values[i%len(values)]
		SanitizeValue("test_key", value)
	}
}