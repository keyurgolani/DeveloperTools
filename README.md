# Developer Utilities MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive, high-performance utility server that consolidates essential development tools into a single, secure service. Built in Go for optimal performance, security, and reliability in production environments.

## 🚀 Features

### 🔐 Cryptography & Security
- **Hash Calculation**: MD5, SHA1, SHA256, SHA512 with hex encoding
- **HMAC Generation**: SHA256/SHA512-based message authentication
- **Password Security**: Argon2id hashing with secure defaults (64MB memory, 3 iterations)
- **Certificate Tools**: X.509 PEM certificate decoding and analysis
- **Security-First**: Constant-time operations, no sensitive data logging

### 📝 Text Processing
- **Case Conversion**: UPPERCASE, lowercase, camelCase, PascalCase, snake_case, kebab-case
- **Text Analysis**: Character/word/line/sentence counts, byte size calculation
- **Regex Testing**: Pattern matching with comprehensive error handling
- **JSON Operations**: Formatting, minification with configurable indentation
- **Text Sorting**: Alphabetical and numerical sorting (ascending/descending)

### 🔄 Data Transformation
- **Base64 Operations**: Standard and URL-safe encoding/decoding
- **URL Operations**: Percent-encoding and decoding
- **JWT Decoding**: Header and payload extraction (no signature verification)
- **Compression**: Gzip and Zlib compression/decompression with security limits

### 🆔 Identifier Generation
- **UUID Generation**: Version 1 and 4 UUIDs with configurable count limits
- **Nano ID Generation**: URL-friendly identifiers with customizable size
- **Cryptographically Secure**: Uses secure random number generators

### ⏰ Time Utilities
- **Format Conversion**: Unix timestamps, ISO 8601, RFC 3339, human-readable
- **Current Time**: Multi-format current time retrieval (all UTC)
- **Timezone Handling**: Consistent UTC output for reliability

### 🌐 Network & Web Tools
- **URL Operations**: Parsing into components and building from parts
- **HTTP Inspection**: Header retrieval with SSRF protection
- **DNS Lookups**: A, AAAA, MX, TXT, NS, CNAME record resolution
- **IP Analysis**: Address validation and classification (private/public/loopback)
- **Security**: SSRF protection, request timeouts, input validation

## 🏗️ Architecture

### Production-Ready Design
- **Modular Monolith**: Clear separation of concerns with module boundaries
- **Security-First**: SSRF protection, rate limiting, input validation
- **Observability**: Structured logging, Prometheus metrics, OpenTelemetry tracing
- **Scalability**: Stateless design for horizontal scaling
- **Reliability**: Graceful shutdown, health checks, error handling

### Technology Stack
- **Language**: Go 1.22+ for performance and security
- **Framework**: Gin for high-performance HTTP handling
- **Containerization**: Multi-stage Docker builds with distroless base
- **Orchestration**: Kubernetes-ready with comprehensive manifests
- **Monitoring**: Prometheus metrics, structured JSON logging
- **Security**: Non-root execution, read-only filesystem, security policies

## 🚀 Quick Start

### Prerequisites
- Go 1.22 or later
- Docker (optional, for containerized deployment)
- Make (optional, for build automation)

### Local Development

```bash
# Setup development environment
make setup

# Run in development mode
make run-dev

# Or run directly
go run ./cmd/server
```

### Using Make (Recommended)

```bash
# See all available commands
make help

# Full development workflow
make ci

# Quick development server
make run-dev

# Run all tests
make test-all

# Build and test Docker image
make docker-test
```

### Docker Deployment

```bash
# Build and run with Docker
make docker-build
make docker-run

# Or use docker-compose for full stack
docker-compose -f deployments/docker-compose.yml up

# With Redis rate limiting
docker-compose -f deployments/docker-compose.yml --profile redis-example up
```

### Kubernetes Deployment

```bash
# Create secrets
kubectl create secret generic dev-utilities-secrets \
  --from-literal=api-keys="your-api-key-1,your-api-key-2" \
  --from-literal=redis-url="redis://redis-service:6379"

# Deploy to Kubernetes
kubectl apply -f deployments/k8s-deployment.yaml

# Check deployment
kubectl get pods -l app=dev-utilities
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `8080` | HTTP server port |
| `SERVER_TLS_ENABLED` | `false` | Enable TLS (requires cert files) |
| `AUTH_METHOD` | `none` | Authentication: `none`, `api_key`, `jwt` |
| `AUTH_API_KEYS` | `""` | Comma-separated API keys |
| `AUTH_JWT_SECRET` | `""` | JWT signing secret |
| `RATE_LIMIT_STORE` | `memory` | Rate limit store: `memory`, `redis` |
| `RATE_LIMIT_REDIS_URL` | `""` | Redis connection URL |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `ARGON_MEMORY` | `65536` | Argon2 memory in KB |
| `ARGON_ITERATIONS` | `3` | Argon2 iterations |
| `ARGON_PARALLELISM` | `4` | Argon2 parallelism |

### Authentication

#### API Key Authentication
```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/crypto/hash
```

#### JWT Authentication
```bash
curl -H "Authorization: Bearer your-jwt-token" \
  http://localhost:8080/api/v1/crypto/hash
```

## 📊 Monitoring & Observability

### Health Checks
- **Liveness**: `GET /health/live` - Basic server responsiveness
- **Readiness**: `GET /health/ready` - Service readiness including dependencies
- **General**: `GET /health` - Overall health status with timestamp

### Metrics
Prometheus-compatible metrics at `/metrics`:
- HTTP request metrics (count, duration, status codes)
- Business metrics per module (crypto operations, text processing, etc.)
- Go runtime metrics (memory, goroutines, GC)
- Rate limiting and security metrics

### Logging
Structured JSON logging with:
- Request ID tracing for distributed debugging
- Sensitive data protection (never logs passwords, keys, etc.)
- Configurable log levels
- Request/response metadata logging

### Tracing
OpenTelemetry support with:
- Jaeger and OTLP exporters
- Configurable sampling rates
- Distributed trace context propagation

## 🔒 Security

### Security Features
- **SSRF Protection**: Blocks access to private/reserved IP ranges
- **Rate Limiting**: Configurable limits per operation type and user
- **Input Validation**: Request size limits, input sanitization
- **Authentication**: Pluggable auth with API key and JWT support
- **Container Security**: Non-root execution, read-only filesystem
- **Network Security**: Kubernetes network policies included

### Security Best Practices
- Constant-time password verification to prevent timing attacks
- Secure Argon2id parameters for password hashing
- No sensitive data in logs or error messages
- Comprehensive input validation and sanitization
- Security-focused Docker image with minimal attack surface

## 🧪 Testing

### Test Coverage
- **Unit Tests**: 85%+ coverage requirement with comprehensive test suite
- **Integration Tests**: Full HTTP endpoint testing with real dependencies
- **End-to-End Tests**: Docker container testing with real scenarios
- **Security Tests**: SSRF protection, timing attack prevention
- **Performance Tests**: Load testing and benchmarking

### Running Tests

```bash
# All tests with coverage
make test-coverage

# Integration tests
make integration-test

# End-to-end tests (requires Docker)
make e2e-test

# Security tests
make security-test

# Performance benchmarks
make performance-test

# Complete test suite
make test-all
```

## 📚 API Documentation

### Interactive Documentation
- **OpenAPI 3.0**: Complete specification in `api/openapi.yml`
- **Generated Docs**: Run `make docs` to generate HTML documentation
- **Live Testing**: Use the interactive API explorer

### Example API Calls

#### Cryptography
```bash
# Hash calculation
curl -X POST http://localhost:8080/api/v1/crypto/hash \
  -H "Content-Type: application/json" \
  -d '{"content": "hello world", "algorithm": "sha256"}'

# Password hashing
curl -X POST http://localhost:8080/api/v1/crypto/password/hash \
  -H "Content-Type: application/json" \
  -d '{"password": "mySecurePassword123"}'
```

#### Text Processing
```bash
# Case conversion
curl -X POST http://localhost:8080/api/v1/text/case \
  -H "Content-Type: application/json" \
  -d '{"content": "hello world", "caseType": "camelCase"}'

# Text analysis
curl -X POST http://localhost:8080/api/v1/text/info \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello world!\nThis is a test."}'
```

#### Network Tools
```bash
# URL parsing
curl -X POST http://localhost:8080/api/v1/web/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/path?param=value", "action": "parse"}'

# IP analysis
curl -X POST http://localhost:8080/api/v1/network/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

## 🚀 Deployment

### Production Deployment
- **Docker**: Multi-stage builds with security hardening
- **Kubernetes**: Production-ready manifests with security policies
- **CI/CD**: GitHub Actions pipeline with comprehensive testing
- **Monitoring**: Prometheus metrics and health checks
- **Scaling**: Horizontal pod autoscaling configuration

### Deployment Options
1. **Docker Compose**: Quick local deployment with optional Redis
2. **Kubernetes**: Production deployment with scaling and monitoring
3. **Binary**: Direct deployment of compiled binary
4. **Cloud**: Cloud-native deployment with managed services

## 🛠️ Development

### Project Structure
```
├── api/                    # OpenAPI specification
├── bin/                    # Built binaries
├── build/                  # Build tools and scripts
│   └── scripts/           # Build and test scripts
├── cmd/                    # Application entry points
│   └── server/            # Main server application
├── deployments/           # Deployment configurations
│   ├── docker-compose.yml # Docker Compose setup
│   └── k8s-deployment.yaml # Kubernetes manifests
├── docs/                  # Documentation
├── internal/              # Internal packages
│   ├── config/           # Configuration management
│   ├── server/           # HTTP server and routing
│   ├── middleware/       # Authentication, rate limiting
│   ├── modules/          # Feature modules
│   ├── logging/          # Structured logging
│   ├── metrics/          # Prometheus metrics
│   └── tracing/          # OpenTelemetry tracing
├── mcp-bridge/           # MCP protocol bridge (Node.js)
├── pkg/                   # Public packages
├── tests/                # Integration and E2E tests
└── .github/workflows/    # CI/CD pipelines
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Run `make pre-commit` to ensure code quality
4. Submit a pull request with comprehensive tests

### Code Quality
- **Linting**: golangci-lint with strict configuration
- **Formatting**: gofmt and gofumpt for consistent style
- **Security**: gosec security scanning
- **Testing**: Comprehensive test suite with coverage requirements
- **Documentation**: Inline documentation and API specs
- **Version Management**: Centralized version information with build-time injection

## 📖 Documentation

- **[API Documentation](docs/API.md)**: Complete API reference
- **[Deployment Guide](docs/deployment.md)**: Deployment instructions and best practices
- **[Operations Runbook](docs/operations.md)**: Operational procedures and troubleshooting
- **[OpenAPI Specification](api/openapi.yml)**: Machine-readable API specification

## 🤝 Support

### Getting Help
- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Comprehensive docs in the `docs/` directory
- **Examples**: Sample requests and responses in API documentation
- **Community**: Contribute to discussions and improvements

### Troubleshooting
- Check the [Operations Runbook](docs/operations.md) for common issues
- Review application logs for error details
- Verify configuration and environment variables
- Test with minimal configuration to isolate issues

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- Built with Go for performance and reliability
- Inspired by the need for consolidated development utilities
- Designed with security and production readiness in mind
- Community-driven development and feedback

---

**Ready to get started?** Run `make setup && make run-dev` to start developing!