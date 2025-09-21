package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger with additional functionality for the application
type Logger struct {
	*slog.Logger
}

// New creates a new logger instance with the specified level
func New(level string) *Logger {
	var logLevel slog.Level

	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Create JSON handler for structured logging
	opts := &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Sanitize sensitive attributes
			if isSensitiveKey(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{Logger: logger}
}

// WithRequestID creates a logger with request ID context
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.Logger.With("request_id", requestID),
	}
}

// WithModule creates a logger with module context
func (l *Logger) WithModule(module string) *Logger {
	return &Logger{
		Logger: l.Logger.With("module", module),
	}
}

// WithContext creates a logger with context values
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract request ID from context if available
	if requestID := ctx.Value("request_id"); requestID != nil {
		return l.WithRequestID(requestID.(string))
	}
	return l
}

// LogError logs an error with additional context
func (l *Logger) LogError(err error, msg string, args ...any) {
	if err != nil {
		args = append(args, "error", err.Error())
	}
	l.Error(msg, args...)
}

// LogRequest logs HTTP request information (without sensitive data)
func (l *Logger) LogRequest(method, path string, status int, duration int64, args ...any) {
	baseArgs := []any{
		"method", method,
		"path", path,
		"status", status,
		"duration_ms", duration,
	}
	
	allArgs := append(baseArgs, args...)
	
	switch {
	case status >= 500:
		l.Error("HTTP request", allArgs...)
	case status >= 400:
		l.Warn("HTTP request", allArgs...)
	default:
		l.Info("HTTP request", allArgs...)
	}
}

// isSensitiveKey checks if a log key contains sensitive information
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

// SanitizeValue sanitizes potentially sensitive values for logging
func SanitizeValue(key string, value interface{}) interface{} {
	if isSensitiveKey(key) {
		return "[REDACTED]"
	}
	
	// If it's a string, check for patterns that might be sensitive
	if str, ok := value.(string); ok {
		if looksLikeSensitiveData(str) {
			return "[REDACTED]"
		}
	}
	
	return value
}

// looksLikeSensitiveData checks if a string looks like sensitive data
func looksLikeSensitiveData(value string) bool {
	// Check for common patterns of sensitive data
	if len(value) == 0 {
		return false
	}
	
	// JWT tokens (3 base64 parts separated by dots)
	if strings.Count(value, ".") == 2 && len(value) > 100 {
		return true
	}
	
	// API keys (long alphanumeric strings)
	if len(value) > 32 && isAlphanumeric(value) {
		return true
	}
	
	// Base64 encoded data (might be sensitive)
	if len(value) > 50 && isBase64Like(value) {
		return true
	}
	
	return false
}

// isAlphanumeric checks if string contains only alphanumeric characters
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// isBase64Like checks if string looks like base64 encoding
func isBase64Like(s string) bool {
	if len(s) == 0 {
		return false
	}
	
	// Check for mixed content (spaces or other non-base64 chars mixed with base64)
	hasSpace := false
	validChars := 0
	
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			hasSpace = true
		} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
		   (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' || r == '-' || r == '_' {
			validChars++
		}
	}
	
	// If it has spaces mixed with base64 chars, it's likely mixed content
	if hasSpace && validChars > 0 {
		return false
	}
	
	// If more than 90% of characters are valid base64 chars (including URL-safe), consider it base64-like
	return float64(validChars)/float64(len(s)) > 0.9
}