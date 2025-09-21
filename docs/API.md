# Developer Utilities MCP Server API Documentation

This document provides comprehensive information about the Developer Utilities MCP Server API.

## Overview

The Developer Utilities MCP Server is a comprehensive, high-performance utility server that consolidates essential development tools into a single service. It provides cryptography, data manipulation, text processing, identifier generation, time utilities, and network tools through a RESTful API.

## Base URL

- **Local Development**: `http://localhost:8080`
- **Production**: `https://api.example.com`

## Authentication

The API supports multiple authentication methods:

### API Key Authentication
Include your API key in the request header:
```
X-API-Key: your-api-key-here
```

### JWT Authentication
Include your JWT token in the Authorization header:
```
Authorization: Bearer your-jwt-token-here
```

### No Authentication (Development)
For development and testing, authentication can be disabled.

## Response Format

All API responses follow a consistent format:

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data varies by endpoint
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": "Additional error details (optional)"
  }
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request format or parameters |
| `AUTHENTICATION_ERROR` | 401 | Missing or invalid authentication |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Endpoint or resource not found |
| `METHOD_NOT_ALLOWED` | 405 | HTTP method not allowed |
| `RATE_LIMIT_ERROR` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Anonymous users**: 60 requests per minute, burst of 10
- **Authenticated users**: 300 requests per minute, burst of 50
- **Crypto operations**: 30 requests per minute, burst of 5 (due to CPU intensity)

Rate limit information is included in response headers:
- `X-RateLimit-Limit`: Request limit per window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Time when the rate limit resets

## Request Tracing

Each request is assigned a unique ID for tracing purposes. The request ID is:
- Returned in the `X-Request-ID` response header
- Included in server logs for debugging
- Can be provided in the `X-Request-ID` request header

## API Endpoints

### Health and Monitoring

#### GET /health
Basic health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2023-12-01T10:00:00Z",
  "service": "dev-utilities"
}
```

#### GET /health/live
Kubernetes liveness probe endpoint.

#### GET /health/ready
Kubernetes readiness probe endpoint.

#### GET /metrics
Prometheus-compatible metrics endpoint.

### Cryptography

#### POST /api/v1/crypto/hash
Calculate hash using various algorithms.

**Request:**
```json
{
  "content": "hello world",
  "algorithm": "sha256"
}
```

**Supported algorithms:** `md5`, `sha1`, `sha256`, `sha512`

**Response:**
```json
{
  "success": true,
  "data": {
    "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    "algorithm": "sha256"
  }
}
```

#### POST /api/v1/crypto/hmac
Generate HMAC using SHA256 or SHA512.

**Request:**
```json
{
  "content": "what do ya want for nothing?",
  "key": "Jefe",
  "algorithm": "sha256"
}
```

#### POST /api/v1/crypto/password/hash
Hash password using Argon2id.

**Request:**
```json
{
  "password": "mySecurePassword123"
}
```

#### POST /api/v1/crypto/password/verify
Verify password against Argon2id hash.

**Request:**
```json
{
  "password": "mySecurePassword123",
  "hash": "$argon2id$v=19$m=65536,t=3,p=4$..."
}
```

#### POST /api/v1/crypto/cert/decode
Decode PEM-encoded X.509 certificate.

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
}
```

### Text Processing

#### POST /api/v1/text/case
Convert text between different case formats.

**Request:**
```json
{
  "content": "hello world example",
  "caseType": "camelCase"
}
```

**Supported case types:**
- `UPPERCASE`
- `lowercase`
- `Title Case`
- `Sentence case`
- `camelCase`
- `PascalCase`
- `snake_case`
- `kebab-case`

#### POST /api/v1/text/info
Analyze text and get detailed statistics.

**Request:**
```json
{
  "content": "Hello world!\nThis is a test."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "characterCount": 25,
    "wordCount": 5,
    "lineCount": 2,
    "sentenceCount": 2,
    "byteSize": 25
  }
}
```

#### POST /api/v1/text/regex
Test regular expression against text.

**Request:**
```json
{
  "content": "Contact us at support@example.com or sales@test.org",
  "pattern": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
  "flags": "g"
}
```

#### POST /api/v1/text/sort
Sort text lines alphabetically or numerically.

**Request:**
```json
{
  "content": "zebra\napple\nbanana\ncherry",
  "order": "asc",
  "sortType": "alpha"
}
```

#### POST /api/v1/data/json/format
Format or minify JSON.

**Request:**
```json
{
  "content": "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}",
  "action": "format",
  "indent": 2
}
```

### Data Transformation

#### POST /api/v1/transform/base64
Encode or decode Base64 data.

**Request:**
```json
{
  "content": "hello world",
  "action": "encode",
  "urlSafe": false
}
```

#### POST /api/v1/transform/url
URL encode or decode data.

**Request:**
```json
{
  "content": "hello world & special chars",
  "action": "encode"
}
```

#### POST /api/v1/transform/jwt/decode
Decode JWT token (without signature verification).

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### POST /api/v1/transform/compress
Compress or decompress data using Gzip or Zlib.

**Request:**
```json
{
  "content": "This is some text that will be compressed",
  "action": "compress",
  "algorithm": "gzip"
}
```

### Identifier Generation

#### POST /api/v1/id/uuid
Generate UUIDs (version 1 or 4).

**Request:**
```json
{
  "version": 4,
  "count": 5
}
```

#### POST /api/v1/id/nanoid
Generate URL-friendly Nano IDs.

**Request:**
```json
{
  "size": 21,
  "count": 5
}
```

### Time Utilities

#### POST /api/v1/time/convert
Convert between different time formats.

**Request:**
```json
{
  "input": "1640995200",
  "inputFormat": "unix",
  "outputFormat": "iso8601"
}
```

**Supported formats:**
- `unix` - Unix timestamp in seconds
- `unix_ms` - Unix timestamp in milliseconds
- `iso8601` - ISO 8601 format
- `rfc3339` - RFC 3339 format
- `human` - Human-readable format

#### GET /api/v1/time/now
Get current time in multiple formats.

**Response:**
```json
{
  "success": true,
  "data": {
    "unixSeconds": 1640995200,
    "unixMilliseconds": 1640995200000,
    "iso8601": "2022-01-01T00:00:00Z",
    "rfc3339": "2022-01-01T00:00:00Z",
    "humanReadable": "January 1, 2022 at 12:00:00 AM UTC"
  }
}
```

### Network Utilities

#### POST /api/v1/web/url
Parse URLs into components or build URLs from components.

**Parse URL:**
```json
{
  "action": "parse",
  "url": "https://example.com:8080/path?param=value#fragment"
}
```

**Build URL:**
```json
{
  "action": "build",
  "parts": {
    "scheme": "https",
    "host": "example.com",
    "path": "/api/v1",
    "query": {
      "param1": "value1",
      "param2": "value2"
    }
  }
}
```

#### POST /api/v1/network/headers
Get HTTP headers from a URL (with SSRF protection).

**Request:**
```json
{
  "url": "https://httpbin.org/headers"
}
```

#### POST /api/v1/network/dns
Perform DNS lookup for various record types.

**Request:**
```json
{
  "domain": "example.com",
  "recordType": "A"
}
```

**Supported record types:** `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`

#### POST /api/v1/network/ip
Analyze and classify IP addresses.

**Request:**
```json
{
  "ip": "8.8.8.8"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ip": "8.8.8.8",
    "version": 4,
    "isPrivate": false,
    "isPublic": true,
    "isLoopback": false
  }
}
```

## Security Considerations

### SSRF Protection
Network operations include Server-Side Request Forgery (SSRF) protection:
- Blocks access to private IP ranges (10.x.x.x, 192.168.x.x, 127.x.x.x)
- Blocks access to reserved IP ranges (169.254.169.254, etc.)
- Disables HTTP redirects
- Implements request timeouts

### Input Validation
- Request body size limited to 1MB
- All inputs are validated and sanitized
- Malicious patterns are blocked

### Rate Limiting
- Prevents DoS attacks through request rate limiting
- Stricter limits for CPU-intensive operations
- Per-client tracking and enforcement

### Logging Security
- Sensitive data is never logged
- Request bodies for crypto operations are not logged
- Only metadata and error information is logged

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- **File**: `api/openapi.yml`
- **Interactive Documentation**: Available when running the server locally

## Development and Testing

### Validation Tools

```bash
# Validate OpenAPI specification
make validate-openapi

# Validate API implementation
make validate-api

# Run all validations
make validate-all

# Generate documentation
make docs
```

### Testing Endpoints

You can test endpoints using curl:

```bash
# Health check
curl http://localhost:8080/health

# Hash calculation
curl -X POST http://localhost:8080/api/v1/crypto/hash \
  -H "Content-Type: application/json" \
  -d '{"content": "hello world", "algorithm": "sha256"}'

# Text case conversion
curl -X POST http://localhost:8080/api/v1/text/case \
  -H "Content-Type: application/json" \
  -d '{"content": "hello world", "caseType": "camelCase"}'
```

## Support and Contributing

For issues, feature requests, or contributions, please visit the project repository.

## License

This project is licensed under the Apache 2.0 License.