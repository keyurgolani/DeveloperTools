# Integration and End-to-End Tests

This directory contains integration, end-to-end, security, and performance tests for the Developer Utilities MCP Server.

## Test Files

### `integration_test.go`
Integration tests that verify the complete application stack:
- HTTP server functionality
- All API endpoints
- Authentication and authorization
- Rate limiting
- Error handling
- Database/Redis integration (if configured)

### `e2e_test.go`
End-to-end tests that test the application as a black box:
- Docker container testing
- Full request/response cycles
- Real network communication
- Production-like scenarios

### `security_test.go`
Security-focused tests:
- Authentication bypass attempts
- Input validation
- SSRF protection
- Rate limiting enforcement
- Timing attack prevention

### `performance_test.go`
Performance and load tests:
- Benchmarking critical paths
- Memory usage analysis
- Concurrent request handling
- Resource utilization

## Running Tests

### Through Makefile (Recommended)
```bash
# Run all integration tests
make integration-test

# Run end-to-end tests
make e2e-test

# Run security tests
make security-test

# Run performance tests
make performance-test

# Run all tests
make test-all
```

### Direct Execution
```bash
# Integration tests
go test -v -tags=integration ./tests/integration_test.go

# E2E tests (requires running server)
go test -v -tags=e2e ./tests/e2e_test.go

# Security tests
go test -v -tags=security ./tests/security_test.go

# Performance tests
go test -v -tags=performance -bench=. -benchmem ./tests/performance_test.go
```

## Test Requirements

### Integration Tests
- No external dependencies required
- Uses in-memory configurations
- Starts test HTTP server automatically

### E2E Tests
- Requires Docker for container testing
- May require external services (Redis) for full testing
- Tests against real network endpoints

### Security Tests
- Tests security boundaries and protections
- May generate intentionally malicious requests
- Validates security configurations

### Performance Tests
- Measures performance characteristics
- Generates load and measures response times
- Analyzes memory usage patterns

## Test Data

Test data and fixtures are embedded in the test files or generated dynamically to avoid external dependencies.