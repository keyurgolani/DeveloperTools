package transform_test

import (
	"encoding/base64"
	"strings"
	"testing"

	. "github.com/keyurgolani/DeveloperTools/internal/modules/transform"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformService_Base64Encode(t *testing.T) {
	service := NewTransformService()

	tests := []struct {
		name     string
		content  string
		urlSafe  bool
		expected string
	}{
		{
			name:     "standard base64 encoding",
			content:  "hello world",
			urlSafe:  false,
			expected: "aGVsbG8gd29ybGQ=",
		},
		{
			name:     "url-safe base64 encoding",
			content:  "hello world",
			urlSafe:  true,
			expected: "aGVsbG8gd29ybGQ=",
		},
		{
			name:     "standard base64 with special chars",
			content:  "hello>world?",
			urlSafe:  false,
			expected: "aGVsbG8+d29ybGQ/",
		},
		{
			name:     "url-safe base64 with special chars",
			content:  "hello>world?",
			urlSafe:  true,
			expected: "aGVsbG8-d29ybGQ_",
		},
		{
			name:     "empty string",
			content:  "",
			urlSafe:  false,
			expected: "",
		},
		{
			name:     "unicode content",
			content:  "Hello 世界",
			urlSafe:  false,
			expected: base64.StdEncoding.EncodeToString([]byte("Hello 世界")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.Base64Encode(tt.content, tt.urlSafe)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTransformService_Base64Decode(t *testing.T) {
	service := NewTransformService()
	tests := getBase64DecodeTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.Base64Decode(tt.content, tt.urlSafe)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid base64 input")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// getBase64DecodeTestCases returns test cases for Base64 decode testing.
func getBase64DecodeTestCases() []struct { //nolint:funlen // test data structure
	name     string
	content  string
	urlSafe  bool
	expected string
	wantErr  bool
} {
	return []struct {
		name     string
		content  string
		urlSafe  bool
		expected string
		wantErr  bool
	}{
		{
			name:     "standard base64 decoding",
			content:  "aGVsbG8gd29ybGQ=",
			urlSafe:  false,
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "url-safe base64 decoding",
			content:  "aGVsbG8gd29ybGQ=",
			urlSafe:  true,
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "standard base64 with special chars",
			content:  "aGVsbG8+d29ybGQ/",
			urlSafe:  false,
			expected: "hello>world?",
			wantErr:  false,
		},
		{
			name:     "url-safe base64 with special chars",
			content:  "aGVsbG8-d29ybGQ_",
			urlSafe:  true,
			expected: "hello>world?",
			wantErr:  false,
		},
		{
			name:     "empty string",
			content:  "",
			urlSafe:  false,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "invalid base64",
			content:  "invalid!!!",
			urlSafe:  false,
			expected: "",
			wantErr:  true,
		},
		{
			name:     "unicode content",
			content:  base64.StdEncoding.EncodeToString([]byte("Hello 世界")),
			urlSafe:  false,
			expected: "Hello 世界",
			wantErr:  false,
		},
	}
}

func TestTransformService_URLEncode(t *testing.T) {
	service := NewTransformService()

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "simple text",
			content:  "hello world",
			expected: "hello+world",
		},
		{
			name:     "special characters",
			content:  "hello@world.com",
			expected: "hello%40world.com",
		},
		{
			name:     "spaces and symbols",
			content:  "hello world & more!",
			expected: "hello+world+%26+more%21",
		},
		{
			name:     "empty string",
			content:  "",
			expected: "",
		},
		{
			name:     "unicode characters",
			content:  "Hello 世界",
			expected: "Hello+%E4%B8%96%E7%95%8C",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.URLEncode(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTransformService_URLDecode(t *testing.T) {
	service := NewTransformService()

	tests := []struct {
		name     string
		content  string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple text",
			content:  "hello+world",
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "special characters",
			content:  "hello%40world.com",
			expected: "hello@world.com",
			wantErr:  false,
		},
		{
			name:     "spaces and symbols",
			content:  "hello+world+%26+more%21",
			expected: "hello world & more!",
			wantErr:  false,
		},
		{
			name:     "empty string",
			content:  "",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "unicode characters",
			content:  "Hello+%E4%B8%96%E7%95%8C",
			expected: "Hello 世界",
			wantErr:  false,
		},
		{
			name:     "invalid encoding",
			content:  "hello%ZZ",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.URLDecode(tt.content)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid URL encoding")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTransformService_DecodeJWT(t *testing.T) {
	service := NewTransformService()
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" // #nosec G101 - test token only //nolint:lll
	tests := getJWTDecodeTestCases(validToken)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.DecodeJWT(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.False(t, result.SignatureVerified)
				assert.NotNil(t, result.Header)
				assert.NotNil(t, result.Payload)

				// Check expected values for valid token
				if tt.token == validToken {
					assert.Equal(t, "HS256", result.Header["alg"])
					assert.Equal(t, "JWT", result.Header["typ"])
					assert.Equal(t, "1234567890", result.Payload["sub"])
					assert.Equal(t, "John Doe", result.Payload["name"])
				}
			}
		})
	}
}

// getJWTDecodeTestCases returns test cases for JWT decode testing.
func getJWTDecodeTestCases(validToken string) []struct {
	name    string
	token   string
	wantErr bool
	errMsg  string
} {
	return []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid JWT token",
			token:   validToken,
			wantErr: false,
		},
		{
			name:    "invalid format - too few parts",
			token:   "invalid.token",
			wantErr: true,
			errMsg:  "invalid JWT format",
		},
		{
			name:    "invalid format - too many parts",
			token:   "invalid.token.with.too.many.parts",
			wantErr: true,
			errMsg:  "invalid JWT format",
		},
		{
			name:    "invalid header encoding",
			token:   "invalid!!!.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
			wantErr: true,
			errMsg:  "invalid JWT header encoding",
		},
		{
			name:    "invalid payload encoding",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid!!!.signature",
			wantErr: true,
			errMsg:  "invalid JWT payload encoding",
		},
		{
			name:    "invalid header JSON",
			token:   "aW52YWxpZC1qc29u.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
			wantErr: true,
			errMsg:  "invalid JWT header JSON",
		},
		{
			name:    "invalid payload JSON",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZC1qc29u.signature",
			wantErr: true,
			errMsg:  "invalid JWT payload JSON",
		},
	}
}

func TestTransformService_Compress(t *testing.T) {
	service := NewTransformService()
	tests := getCompressionTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.Compress(tt.content, tt.algorithm, tt.action)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)

				// Verify it's valid base64
				_, err := base64.StdEncoding.DecodeString(result)
				assert.NoError(t, err, "Result should be valid base64")
			}
		})
	}
}

// getCompressionTestCases returns test cases for compression testing.
func getCompressionTestCases() []struct {
	name      string
	content   string
	algorithm string
	action    string
	wantErr   bool
	errMsg    string
} {
	testContent := "Hello, World! This is a test string for compression."
	return []struct {
		name      string
		content   string
		algorithm string
		action    string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "gzip compression",
			content:   testContent,
			algorithm: "gzip",
			action:    "compress",
			wantErr:   false,
		},
		{
			name:      "zlib compression",
			content:   testContent,
			algorithm: "zlib",
			action:    "compress",
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm",
			content:   testContent,
			algorithm: "bzip2",
			action:    "compress",
			wantErr:   true,
			errMsg:    "unsupported compression algorithm",
		},
		{
			name:      "invalid action",
			content:   testContent,
			algorithm: "gzip",
			action:    "invalid",
			wantErr:   true,
			errMsg:    "invalid action",
		},
		{
			name:      "input too large",
			content:   strings.Repeat("a", 1024*1024+1), // 1MB + 1 byte
			algorithm: "gzip",
			action:    "compress",
			wantErr:   true,
			errMsg:    "input too large",
		},
	}
}

func TestTransformService_CompressDecompress(t *testing.T) {
	service := NewTransformService()

	testContent := "Hello, World! This is a test string for compression and decompression."

	algorithms := []string{"gzip", "zlib"}

	for _, algorithm := range algorithms {
		t.Run(algorithm+" round trip", func(t *testing.T) {
			// Compress
			compressed, err := service.Compress(testContent, algorithm, "compress")
			require.NoError(t, err)
			require.NotEmpty(t, compressed)

			// Decompress
			decompressed, err := service.Compress(compressed, algorithm, "decompress")
			require.NoError(t, err)
			assert.Equal(t, testContent, decompressed)
		})
	}
}

func TestTransformService_DecompressErrors(t *testing.T) {
	service := NewTransformService()

	tests := []struct {
		name      string
		content   string
		algorithm string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "invalid base64 input",
			content:   "invalid!!!",
			algorithm: "gzip",
			wantErr:   true,
			errMsg:    "invalid base64 input",
		},
		{
			name:      "invalid gzip data",
			content:   base64.StdEncoding.EncodeToString([]byte("invalid gzip data")),
			algorithm: "gzip",
			wantErr:   true,
			errMsg:    "failed to create gzip reader",
		},
		{
			name:      "invalid zlib data",
			content:   base64.StdEncoding.EncodeToString([]byte("invalid zlib data")),
			algorithm: "zlib",
			wantErr:   true,
			errMsg:    "failed to create zlib reader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.Compress(tt.content, tt.algorithm, "decompress")
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
			assert.Empty(t, result)
		})
	}
}
