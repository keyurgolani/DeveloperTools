#!/bin/bash

# CI Setup Validation Script
# This script validates that the local environment matches CI expectations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔍 Validating CI setup compatibility..."
echo "======================================"

# Check Go version
print_status "Checking Go version..."
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
if [[ "$GO_VERSION" =~ ^1\.(2[2-9]|[3-9][0-9]) ]]; then
    print_success "Go version: $GO_VERSION (>= 1.22)"
else
    print_error "Go version: $GO_VERSION (< 1.22 required)"
    exit 1
fi

# Check required tools
print_status "Checking required tools..."

# golangci-lint
if command -v golangci-lint >/dev/null 2>&1; then
    LINT_VERSION=$(golangci-lint version 2>/dev/null | head -1 || echo "unknown")
    print_success "golangci-lint: $LINT_VERSION"
else
    print_warning "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
fi

# gosec
if command -v gosec >/dev/null 2>&1; then
    GOSEC_VERSION=$(gosec -version 2>/dev/null || echo "unknown")
    print_success "gosec: $GOSEC_VERSION"
else
    print_warning "gosec not found. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

# swagger-cli
if command -v swagger-cli >/dev/null 2>&1; then
    SWAGGER_VERSION=$(swagger-cli --version 2>/dev/null || echo "unknown")
    print_success "swagger-cli: $SWAGGER_VERSION"
else
    print_warning "swagger-cli not found. Install with: npm install -g @apidevtools/swagger-cli"
fi

# Check workspace status
print_status "Checking workspace status..."
if [ -n "$(git status --porcelain)" ]; then
    print_warning "Workspace has uncommitted changes:"
    git status --porcelain
    print_warning "This may affect CI validation"
else
    print_success "Workspace is clean"
fi

# Check Go modules
print_status "Validating Go modules..."
if go mod verify && go mod tidy -diff; then
    print_success "Go modules are valid and tidy"
else
    print_error "Go modules validation failed"
    print_error "Run 'go mod tidy' to fix"
    exit 1
fi

# Check build
print_status "Testing build..."
if go build -v ./... >/dev/null 2>&1; then
    print_success "All packages build successfully"
else
    print_error "Build failed"
    exit 1
fi

# Check tests
print_status "Running quick test validation..."
if go test -short ./internal/... ./pkg/... >/dev/null 2>&1; then
    print_success "Quick tests pass"
else
    print_warning "Some tests failed (run 'make test' for details)"
fi

# Check test coverage
print_status "Checking test coverage..."
if go test -coverprofile=coverage.out -covermode=atomic ./internal/... ./pkg/... >/dev/null 2>&1; then
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    if awk "BEGIN {exit !($COVERAGE >= 78)}"; then
        print_success "Test coverage: ${COVERAGE}% (>= 78%)"
    else
        print_warning "Test coverage: ${COVERAGE}% (< 78%)"
        print_warning "CI requires 78% coverage"
        print_warning "This may cause CI to fail"
    fi
    rm -f coverage.out
else
    print_warning "Failed to generate coverage report"
fi

# Check OpenAPI spec
print_status "Validating OpenAPI specification..."
if [ -f "api/openapi.yml" ]; then
    if command -v swagger-cli >/dev/null 2>&1; then
        if swagger-cli validate api/openapi.yml >/dev/null 2>&1; then
            print_success "OpenAPI specification is valid"
        else
            print_error "OpenAPI specification validation failed"
            exit 1
        fi
    else
        print_warning "Cannot validate OpenAPI spec (swagger-cli not installed)"
    fi
else
    print_error "OpenAPI specification not found at api/openapi.yml"
    exit 1
fi

# Check Docker
print_status "Checking Docker availability..."
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        print_success "Docker is available and running"
        
        # Check Docker Compose
        if command -v docker-compose >/dev/null 2>&1; then
            COMPOSE_VERSION=$(docker-compose version --short 2>/dev/null || echo "unknown")
            print_success "docker-compose: $COMPOSE_VERSION"
        elif docker compose version >/dev/null 2>&1; then
            COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "unknown")
            print_success "docker compose: $COMPOSE_VERSION"
        else
            print_warning "Neither docker-compose nor docker compose found"
            print_warning "E2E tests will fall back to local mode"
        fi
    else
        print_warning "Docker is installed but not running"
        print_warning "Some CI tests may fail without Docker"
    fi
else
    print_warning "Docker not found"
    print_warning "Some CI tests may fail without Docker"
fi

# Summary
echo ""
echo "======================================"
print_success "🎉 CI setup validation completed!"
echo ""
echo "💡 To run the same checks as CI:"
echo "   • make pre-commit    - Run pre-commit validation"
echo "   • make ci           - Run full CI pipeline locally"
echo "   • make test-all     - Run all test suites"
echo ""
echo "🔧 If issues persist in CI:"
echo "   • Check GitHub Actions logs for specific errors"
echo "   • Ensure all files are committed and pushed"
echo "   • Verify no platform-specific differences"