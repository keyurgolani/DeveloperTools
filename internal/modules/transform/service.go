package transform

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// TransformService defines the interface for transformation operations
type TransformService interface {
	Base64Encode(content string, urlSafe bool) string
	Base64Decode(content string, urlSafe bool) (string, error)
	URLEncode(content string) string
	URLDecode(content string) (string, error)
	DecodeJWT(token string) (*JWTDecodeResponse, error)
	Compress(content, algorithm, action string) (string, error)
}

// transformService implements the TransformService interface
type transformService struct{}

// NewTransformService creates a new instance of TransformService
func NewTransformService() TransformService {
	return &transformService{}
}

// Base64Encode encodes content to Base64
func (s *transformService) Base64Encode(content string, urlSafe bool) string {
	if urlSafe {
		return base64.URLEncoding.EncodeToString([]byte(content))
	}
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// Base64Decode decodes Base64 content
func (s *transformService) Base64Decode(content string, urlSafe bool) (string, error) {
	var decoded []byte
	var err error
	
	if urlSafe {
		decoded, err = base64.URLEncoding.DecodeString(content)
	} else {
		decoded, err = base64.StdEncoding.DecodeString(content)
	}
	
	if err != nil {
		return "", fmt.Errorf("invalid base64 input: %w", err)
	}
	
	return string(decoded), nil
}

// URLEncode performs URL percent-encoding
func (s *transformService) URLEncode(content string) string {
	return url.QueryEscape(content)
}

// URLDecode performs URL percent-decoding
func (s *transformService) URLDecode(content string) (string, error) {
	decoded, err := url.QueryUnescape(content)
	if err != nil {
		return "", fmt.Errorf("invalid URL encoding: %w", err)
	}
	return decoded, nil
}

// DecodeJWT decodes a JWT token without signature verification
func (s *transformService) DecodeJWT(token string) (*JWTDecodeResponse, error) {
	// Split token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header (URL-safe Base64 without padding)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header encoding: %w", err)
	}

	// Decode payload (URL-safe Base64 without padding)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	// Parse header JSON
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}

	// Parse payload JSON
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	return &JWTDecodeResponse{
		Header:            header,
		Payload:           payload,
		SignatureVerified: false, // We don't verify signatures
	}, nil
}

// Compress performs compression or decompression with security controls
func (s *transformService) Compress(content, algorithm, action string) (string, error) {
	const MaxCompressionInput = 1024 * 1024 // 1MB limit to prevent zip bombs

	if action == "compress" {
		// Check input size limit
		if len(content) > MaxCompressionInput {
			return "", fmt.Errorf("input too large: %d bytes exceeds limit of %d bytes", len(content), MaxCompressionInput)
		}

		var buf bytes.Buffer
		var err error

		switch algorithm {
		case "gzip":
			writer := gzip.NewWriter(&buf)
			_, err = writer.Write([]byte(content))
			if err == nil {
				err = writer.Close()
			}
		case "zlib":
			writer := zlib.NewWriter(&buf)
			_, err = writer.Write([]byte(content))
			if err == nil {
				err = writer.Close()
			}
		default:
			return "", fmt.Errorf("unsupported compression algorithm: %s", algorithm)
		}

		if err != nil {
			return "", fmt.Errorf("compression failed: %w", err)
		}

		// Return Base64-encoded compressed data
		return base64.StdEncoding.EncodeToString(buf.Bytes()), nil

	} else if action == "decompress" {
		// Decode Base64 input
		compressedData, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", fmt.Errorf("invalid base64 input: %w", err)
		}

		// Check compressed data size limit
		if len(compressedData) > MaxCompressionInput {
			return "", fmt.Errorf("compressed data too large: %d bytes exceeds limit of %d bytes", len(compressedData), MaxCompressionInput)
		}

		var reader interface {
			Read([]byte) (int, error)
		}

		switch algorithm {
		case "gzip":
			reader, err = gzip.NewReader(bytes.NewReader(compressedData))
			if err != nil {
				return "", fmt.Errorf("failed to create gzip reader: %w", err)
			}
		case "zlib":
			reader, err = zlib.NewReader(bytes.NewReader(compressedData))
			if err != nil {
				return "", fmt.Errorf("failed to create zlib reader: %w", err)
			}
		default:
			return "", fmt.Errorf("unsupported compression algorithm: %s", algorithm)
		}

		// Read decompressed data with size limit
		var buf bytes.Buffer
		limitedReader := &io.LimitedReader{R: reader, N: MaxCompressionInput}
		_, err = buf.ReadFrom(limitedReader)
		if err != nil {
			return "", fmt.Errorf("decompression failed: %w", err)
		}

		return buf.String(), nil
	}

	return "", fmt.Errorf("invalid action: %s", action)
}