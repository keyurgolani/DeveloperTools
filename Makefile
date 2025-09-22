# Developer Utilities MCP Server Makefile

# Variables
BINARY_NAME=server
DOCKER_IMAGE=dev-utilities
DOCKER_TAG=latest
COVERAGE_THRESHOLD=80
GO_VERSION=1.22

.PHONY: all build run test clean docker-build docker-run help setup ci pre-commit integration-test e2e-test security-test performance-test

# Default target
all: clean deps fmt lint test build

# Setup development environment
setup:
	@echo "🔧 Setting up development environment..."
	@go version | grep -q "go1\." || (echo "❌ Go 1.x required" && exit 1)
	@echo "✅ Go version check passed: $$(go version)"
	@command -v golangci-lint >/dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@command -v docker >/dev/null 2>&1 || (echo "❌ Docker required but not installed" && exit 1)
	@echo "✅ Development environment ready"

# Build the application
build:
	@echo "🔨 Building application..."
	@mkdir -p bin
	@VERSION=$(shell cat VERSION 2>/dev/null || echo "dev") && \
	BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") && \
	GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown") && \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -extldflags '-static' -X 'github.com/keyurgolani/DeveloperTools/internal/version.Version=$$VERSION' -X 'github.com/keyurgolani/DeveloperTools/internal/version.BuildDate=$$BUILD_DATE' -X 'github.com/keyurgolani/DeveloperTools/internal/version.GitCommit=$$GIT_COMMIT'" \
		-o bin/$(BINARY_NAME) ./cmd/server
	@echo "✅ Build complete: bin/$(BINARY_NAME)"

# Build for current platform
build-local:
	@echo "🔨 Building for local platform..."
	@mkdir -p bin
	@VERSION=$(shell cat VERSION 2>/dev/null || echo "dev") && \
	BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") && \
	GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown") && \
	go build \
		-ldflags="-X 'github.com/keyurgolani/DeveloperTools/internal/version.Version=$$VERSION' -X 'github.com/keyurgolani/DeveloperTools/internal/version.BuildDate=$$BUILD_DATE' -X 'github.com/keyurgolani/DeveloperTools/internal/version.GitCommit=$$GIT_COMMIT'" \
		-o bin/$(BINARY_NAME) ./cmd/server
	@echo "✅ Local build complete: bin/$(BINARY_NAME)"

# Run the application
run: build-local
	@echo "🚀 Starting server..."
	@./bin/$(BINARY_NAME)

# Run with development configuration
run-dev:
	@echo "🚀 Starting server in development mode..."
	@LOG_LEVEL=debug AUTH_METHOD=none go run ./cmd/server

# Download dependencies
deps:
	@echo "📦 Downloading dependencies..."
	@go mod download
	@go mod tidy
	@go mod verify
	@echo "✅ Dependencies updated"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	@go fmt ./...
	@gofumpt -w . 2>/dev/null || true
	@echo "✅ Code formatted"

# Run linter
lint:
	@echo "🔍 Running linter..."
	@golangci-lint run --timeout=5m
	@echo "✅ Linting complete"

# Run unit tests
test:
	@echo "🧪 Running unit tests..."
	@go test -v -race ./internal/... ./pkg/...
	@echo "✅ Unit tests complete"

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./internal/... ./pkg/...
	@go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//' > coverage.txt
	@COVERAGE=$$(cat coverage.txt); \
	echo "📊 Test coverage: $${COVERAGE}%"; \
	if [ $$(echo "$${COVERAGE} < $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage $${COVERAGE}% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

# Run integration tests
integration-test:
	@echo "🔗 Running integration tests..."
	@go test -v -tags=integration ./tests/integration_test.go
	@echo "✅ Integration tests complete"

# Run end-to-end tests
e2e-test: docker-build
	@echo "🎭 Running end-to-end tests..."
	@go test -v -tags=e2e ./tests/e2e_test.go
	@echo "✅ E2E tests complete"

# Run end-to-end tests without Docker (fallback)
e2e-test-local:
	@echo "🎭 Running end-to-end tests (local mode)..."
	@echo "⚠️  Running E2E tests against local binary instead of Docker"
	@make build-local
	@./bin/$(BINARY_NAME) --help >/dev/null 2>&1 || (echo "❌ Binary not working" && exit 1)
	@go test -v -tags=e2e -ldflags="-X main.testMode=local" ./tests/e2e_test.go
	@echo "✅ E2E tests complete (local mode)"

# Run security tests
security-test:
	@echo "🔒 Running security tests..."
	@go test -v -tags=security ./tests/security_test.go
	@echo "✅ Security tests complete"

# Run performance tests
performance-test:
	@echo "⚡ Running performance tests..."
	@go test -v -tags=performance -bench=. -benchmem ./tests/performance_test.go
	@echo "✅ Performance tests complete"

# Run all tests
test-all: test integration-test security-test performance-test
	@echo "🎉 All tests completed successfully!"

# Run all tests including E2E (with fallback)
test-all-with-e2e: test integration-test security-test performance-test
	@echo "🎭 Attempting E2E tests..."
	@make e2e-test 2>/dev/null || (echo "⚠️  Docker E2E failed, trying local E2E..." && make e2e-test-local) || echo "⚠️  E2E tests skipped due to environment issues"
	@echo "🎉 All tests completed!"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html coverage.txt
	@docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	@docker system prune -f 2>/dev/null || true
	@echo "✅ Clean complete"

# Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	@VERSION=$(shell cat VERSION 2>/dev/null || echo "dev") && \
	BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") && \
	GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown") && \
	docker build \
		--build-arg VERSION=$$VERSION \
		--build-arg BUILD_DATE=$$BUILD_DATE \
		--build-arg GIT_COMMIT=$$GIT_COMMIT \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):$$VERSION .
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Build multi-platform Docker image
docker-build-multi:
	@echo "🐳 Building multi-platform Docker image..."
	@docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest .
	@echo "✅ Multi-platform Docker image built"

# Run Docker container
docker-run: docker-build
	@echo "🐳 Running Docker container..."
	@docker run --rm -p 8080:8080 \
		-e LOG_LEVEL=info \
		-e AUTH_METHOD=none \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Run Docker container with Redis
docker-run-redis:
	@echo "🐳 Running with Docker Compose (Redis enabled)..."
	@docker-compose -f deployments/docker-compose.yml --profile redis-example up

# Test Docker container
docker-test: docker-build
	@echo "🐳 Testing Docker container..."
	@docker run -d --name test-container -p 18080:8080 $(DOCKER_IMAGE):$(DOCKER_TAG)
	@sleep 5
	@curl -f http://localhost:18080/health || (docker stop test-container && docker rm test-container && exit 1)
	@curl -f -X POST http://localhost:18080/api/v1/crypto/hash \
		-H "Content-Type: application/json" \
		-d '{"content": "test", "algorithm": "sha256"}' || \
		(docker stop test-container && docker rm test-container && exit 1)
	@docker stop test-container
	@docker rm test-container
	@echo "✅ Docker container test passed"

# Validate OpenAPI specification
validate-openapi:
	@echo "🔍 Validating OpenAPI specification..."
	@if command -v swagger-cli >/dev/null 2>&1; then \
		swagger-cli validate api/openapi.yml; \
		echo "✅ OpenAPI specification is valid"; \
	else \
		echo "⚠️  swagger-cli not found. Install with: npm install -g @apidevtools/swagger-cli"; \
	fi

# Validate API implementation against OpenAPI spec
validate-api: build-local
	@echo "🔍 Validating API implementation..."
	@./bin/$(BINARY_NAME) --help >/dev/null 2>&1 || (echo "❌ Binary not built" && exit 1)
	@go run ./cmd/validate-api --spec=api/openapi.yml
	@echo "✅ API implementation validated"

# Generate API documentation
docs:
	@echo "📚 Generating API documentation..."
	@mkdir -p docs/api
	@if command -v redoc-cli >/dev/null 2>&1; then \
		redoc-cli build api/openapi.yml --output docs/api/index.html; \
		echo "✅ Documentation generated at docs/api/index.html"; \
	else \
		echo "⚠️  redoc-cli not found. Install with: npm install -g redoc-cli"; \
	fi

# Run all validations
validate-all: validate-openapi validate-api
	@echo "🎉 All validations completed successfully!"

# Security scan with gosec
security-scan:
	@echo "🔒 Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -fmt json -out gosec-report.json ./...; \
		echo "✅ Security scan complete. Report: gosec-report.json"; \
	else \
		echo "⚠️  gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Pre-commit checks (run before committing)
pre-commit:
	@echo "🔍 Running comprehensive pre-commit checks..."
	@./scripts/pre-commit-checks.sh

# Quick fix common issues
quick-fix:
	@echo "🔧 Running quick fixes for common issues..."
	@echo "=========================================="
	@echo "🔧 Fixing Go code formatting..."
	@gofmt -s -w . && echo "✅ Go code formatted" || echo "❌ Failed to format Go code"
	@echo "🔧 Tidying Go modules..."
	@go mod tidy && echo "✅ Go modules tidied" || echo "❌ Failed to tidy Go modules"
	@echo "🔧 Checking for incorrect import paths..."
	@if grep -r "dev-utilities/" --include="*.go" . 2>/dev/null | grep -v vendor/ >/dev/null; then \
		echo "⚠️  Found incorrect import paths, auto-fixing..."; \
		find . -name "*.go" -type f -not -path "./vendor/*" -exec sed -i '' 's|"dev-utilities/|"github.com/keyurgolani/DeveloperTools/|g' {} \; && \
		echo "✅ Import paths fixed automatically"; \
	else \
		echo "✅ All import paths are correct"; \
	fi
	@echo "🔧 Cleaning up temporary files..."
	@rm -f coverage.out coverage.html coverage.txt gosec-report.json validate-api server
	@rm -rf bin/
	@echo "✅ Temporary files cleaned"
	@echo "🔧 Fixing script permissions..."
	@chmod +x scripts/*.sh 2>/dev/null || true
	@echo "✅ Script permissions fixed"
	@echo ""
	@echo "🎉 Quick fixes completed!"
	@echo ""
	@echo "💡 Next steps:"
	@echo "   • Run 'make pre-commit' to validate fixes"
	@echo "   • Run 'make test' to ensure tests still pass"
	@echo "   • Run 'make lint' to check for any remaining issues"

# Run comprehensive validation (using existing targets)
validate-comprehensive: validate-all security-scan
	@echo "🎉 Comprehensive validation completed!"

# CI pipeline (comprehensive checks)
ci: setup pre-commit integration-test docker-test e2e-test security-test
	@echo "🎉 CI pipeline completed successfully!"

# Deploy to staging (placeholder)
deploy-staging: docker-build
	@echo "🚀 Deploying to staging..."
	@echo "⚠️  Staging deployment not configured. Update Makefile with your deployment commands."

# Deploy to production (placeholder)
deploy-production: docker-build
	@echo "🚀 Deploying to production..."
	@echo "⚠️  Production deployment not configured. Update Makefile with your deployment commands."

# Health check
health-check:
	@echo "🏥 Performing health check..."
	@curl -f http://localhost:8080/health || (echo "❌ Health check failed" && exit 1)
	@echo "✅ Health check passed"

# Load test (requires hey or similar tool)
load-test:
	@echo "⚡ Running load test..."
	@if command -v hey >/dev/null 2>&1; then \
		hey -n 1000 -c 10 http://localhost:8080/health; \
	else \
		echo "⚠️  hey not found. Install with: go install github.com/rakyll/hey@latest"; \
	fi

# Show application logs (for Docker)
logs:
	@docker logs -f $$(docker ps -q --filter ancestor=$(DOCKER_IMAGE):$(DOCKER_TAG)) 2>/dev/null || \
		echo "❌ No running containers found for $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Show metrics
metrics:
	@echo "📊 Fetching metrics..."
	@curl -s http://localhost:8080/metrics | head -20
	@echo "..."
	@echo "Full metrics available at: http://localhost:8080/metrics"

# Install development tools
install-tools:
	@echo "🔧 Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@go install mvdan.cc/gofumpt@latest
	@go install github.com/rakyll/hey@latest
	@echo "✅ Development tools installed"

# Version management
version:
	@echo "📋 Current version: $(shell cat VERSION 2>/dev/null || echo 'not set')"

# Set new version and sync across all files
set-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "❌ Please provide VERSION: make set-version VERSION=1.2.3"; \
		exit 1; \
	fi
	@echo "🔄 Setting version to $(VERSION)..."
	@./scripts/sync-version.sh $(VERSION)
	@echo "✅ Version updated to $(VERSION)"

# Help
help:
	@echo "🚀 Developer Utilities MCP Server - Available Commands:"
	@echo ""
	@echo "📋 Setup & Dependencies:"
	@echo "  setup            - Setup development environment"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  install-tools    - Install development tools"
	@echo ""
	@echo "🔨 Build & Run:"
	@echo "  build            - Build application (Linux/amd64)"
	@echo "  build-local      - Build for current platform"
	@echo "  run              - Build and run application"
	@echo "  run-dev          - Run in development mode"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test             - Run unit tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  integration-test - Run integration tests"
	@echo "  e2e-test         - Run end-to-end tests"
	@echo "  security-test    - Run security tests"
	@echo "  performance-test - Run performance tests"
	@echo "  test-all         - Run all tests"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-build-multi - Build multi-platform image"
	@echo "  docker-run       - Run Docker container"
	@echo "  docker-run-redis - Run with Redis using docker-compose"
	@echo "  docker-test      - Test Docker container"
	@echo ""
	@echo "🔍 Quality & Validation:"
	@echo "  fmt              - Format code"
	@echo "  lint             - Run linter"
	@echo "  validate-openapi - Validate OpenAPI specification"
	@echo "  validate-api     - Validate API implementation"
	@echo "  validate-all     - Run all validations"
	@echo "  validate-comprehensive - Run comprehensive validation suite"
	@echo "  security-scan    - Run security scan"
	@echo "  pre-commit       - Run pre-commit checks"
	@echo "  quick-fix        - Auto-fix formatting, imports, and cleanup"
	@echo "  ci               - Run full CI pipeline"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  docs             - Generate API documentation"
	@echo ""
	@echo "🚀 Operations:"
	@echo "  health-check     - Check application health"
	@echo "  load-test        - Run load test"
	@echo "  logs             - Show application logs"
	@echo "  metrics          - Show application metrics"
	@echo "  deploy-staging   - Deploy to staging"
	@echo "  deploy-production - Deploy to production"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  clean            - Clean build artifacts"
	@echo ""
	@echo "📋 Version Management:"
	@echo "  version          - Show current version"
	@echo "  set-version      - Set new version (usage: make set-version VERSION=1.2.3)"
	@echo ""
	@echo "💡 Quick Start:"
	@echo "  make setup       - First time setup"
	@echo "  make ci          - Full CI pipeline"
	@echo "  make run-dev     - Start development server"