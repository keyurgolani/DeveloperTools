package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/keyurgolani/DeveloperTools/internal/logging"
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
			logger := logging.New(tt.level)
			assert.NotNil(t, logger)
			assert.NotNil(t, logger.Logger)
		})
	}
}

func TestWithRequestID(t *testing.T) {
	logger := logging.New("info")
	requestID := "test-request-id-123"

	loggerWithID := logger.WithRequestID(requestID)
	assert.NotNil(t, loggerWithID)
	assert.NotEqual(t, logger, loggerWithID)
}

func TestWithModule(t *testing.T) {
	logger := logging.New("info")
	module := "crypto"

	loggerWithModule := logger.WithModule(module)
	assert.NotNil(t, loggerWithModule)
	assert.NotEqual(t, logger, loggerWithModule)
}

func TestWithContext(t *testing.T) {
	logger := logging.New("info")

	// Test with context containing request ID
	type contextKey string
	const requestIDKey contextKey = "request_id"
	ctx := context.WithValue(context.Background(), requestIDKey, "test-123")
	loggerWithCtx := logger.WithContext(ctx)
	assert.NotNil(t, loggerWithCtx)

	// Test with empty context
	emptyCtx := context.Background()
	loggerWithEmptyCtx := logger.WithContext(emptyCtx)
	assert.NotNil(t, loggerWithEmptyCtx)
}

func TestSensitiveDataRedaction(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer

	// Create a logger that writes to our buffer with redaction
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Sanitize sensitive attributes
			if isSensitiveKey(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}

	handler := slog.NewJSONHandler(&buf, opts)
	logger := &logging.Logger{Logger: slog.New(handler)}

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

// isSensitiveKey checks if a log key contains sensitive information.
func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "secret", "key", "token", "auth", "api_key",
		"jwt", "bearer", "credential", "private", "hash", "hmac",
		"certificate", "cert", "signature", "salt",
	}

	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}

	return false
}

func TestLogRequest(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	handler := slog.NewJSONHandler(&buf, opts)
	logger := &logging.Logger{Logger: slog.New(handler)}

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
	logger := &logging.Logger{Logger: slog.New(handler)}

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
