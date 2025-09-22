#!/bin/bash

# Pre-commit validation script for Developer Tools MCP Server
# This script runs all the checks that should pass before committing code

set -e  # Exit on any error

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

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run a check and track results
run_check() {
    local check_name="$1"
    local check_command="$2"
    
    print_status "Running $check_name..."
    
    if eval "$check_command"; then
        print_success "$check_name passed"
        return 0
    else
        print_error "$check_name failed"
        return 1
    fi
}

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Track individual check results
declare -a FAILED_CHECK_NAMES=()

# Function to increment counters
increment_check() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ $? -eq 0 ]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("$1")
    fi
}

echo "🔍 Running pre-commit validation checks..."
echo "=========================================="

# Check 1: Go formatting
print_status "Checking Go code formatting..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
UNFORMATTED_FILES=$(gofmt -s -l . 2>/dev/null | grep -v vendor/ || true)
if [ -n "$UNFORMATTED_FILES" ]; then
    print_error "The following files are not properly formatted:"
    echo "$UNFORMATTED_FILES"
    print_error "Run 'make fmt' or 'gofmt -s -w .' to fix formatting issues"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Go formatting")
else
    print_success "Go code formatting is correct"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi

# Check 2: Import path validation
print_status "Checking for incorrect import paths..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
INCORRECT_IMPORTS=$(grep -r "dev-utilities/" --include="*.go" . 2>/dev/null | grep -v vendor/ || true)
if [ -n "$INCORRECT_IMPORTS" ]; then
    print_error "Found incorrect import paths (should use github.com/keyurgolani/DeveloperTools/):"
    echo "$INCORRECT_IMPORTS"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Import paths")
else
    print_success "All import paths are correct"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi

# Check 3: Go modules
print_status "Validating Go modules..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if go mod verify && go mod tidy -diff; then
    print_success "Go modules are valid and tidy"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    print_error "Go modules validation failed. Run 'go mod tidy' to fix"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Go modules")
fi

# Check 4: Build validation
print_status "Checking if all packages build successfully..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if go build -v ./...; then
    print_success "All packages build successfully"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    print_error "Build validation failed"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Build validation")
fi

# Check 5: OpenAPI validation
print_status "Validating OpenAPI specification..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if command_exists swagger-cli; then
    if swagger-cli validate api/openapi.yml; then
        print_success "OpenAPI specification is valid"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        print_error "OpenAPI specification validation failed"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("OpenAPI validation")
    fi
else
    print_warning "swagger-cli not found. Install with: npm install -g @apidevtools/swagger-cli"
    print_warning "Skipping OpenAPI validation"
    TOTAL_CHECKS=$((TOTAL_CHECKS - 1))
fi

# Check 6: Linting
print_status "Running golangci-lint..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if command_exists golangci-lint; then
    if golangci-lint run --timeout=5m; then
        print_success "Linting passed"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        print_error "Linting failed"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("Linting")
    fi
else
    print_warning "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    print_warning "Skipping linting"
    TOTAL_CHECKS=$((TOTAL_CHECKS - 1))
fi

# Check 7: Unit tests
print_status "Running unit tests..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if go test -v -race ./internal/... ./pkg/...; then
    print_success "Unit tests passed"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    print_error "Unit tests failed"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Unit tests")
fi

# Check 8: Test coverage
print_status "Checking test coverage..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
COVERAGE_THRESHOLD=75  # Lower threshold for pre-commit, CI can enforce higher
if go test -coverprofile=coverage.out -covermode=atomic ./internal/... ./pkg/... >/dev/null 2>&1; then
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "$COVERAGE >= $COVERAGE_THRESHOLD" | bc -l) )); then
        print_success "Test coverage: ${COVERAGE}% (>= ${COVERAGE_THRESHOLD}%)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        print_error "Test coverage: ${COVERAGE}% (< ${COVERAGE_THRESHOLD}%)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("Test coverage")
    fi
    rm -f coverage.out
else
    print_error "Failed to generate coverage report"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("Test coverage")
fi

# Check 9: Security scan (if gosec is available)
if command_exists gosec; then
    print_status "Running security scan..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if gosec -quiet ./...; then
        print_success "Security scan passed"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        print_error "Security scan found issues"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("Security scan")
    fi
fi

# Check 10: Validate API implementation
print_status "Building validate-api tool..."
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if go build -o validate-api ./cmd/validate-api; then
    if ./validate-api --spec=api/openapi.yml; then
        print_success "API implementation validation passed"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        print_error "API implementation validation failed"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        FAILED_CHECK_NAMES+=("API validation")
    fi
    rm -f validate-api
else
    print_error "Failed to build validate-api tool"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    FAILED_CHECK_NAMES+=("API validation build")
fi

# Summary
echo ""
echo "=========================================="
echo "📊 Pre-commit validation summary:"
echo "   Total checks: $TOTAL_CHECKS"
echo "   Passed: $PASSED_CHECKS"
echo "   Failed: $FAILED_CHECKS"

if [ $FAILED_CHECKS -eq 0 ]; then
    print_success "🎉 All pre-commit checks passed! Ready to commit."
    exit 0
else
    print_error "❌ $FAILED_CHECKS check(s) failed:"
    for check in "${FAILED_CHECK_NAMES[@]}"; do
        echo "   - $check"
    done
    echo ""
    print_error "Please fix the issues above before committing."
    echo ""
    echo "💡 Quick fixes:"
    echo "   - Run 'make fmt' to fix formatting"
    echo "   - Run 'make lint' to see linting issues"
    echo "   - Run 'make test' to run tests"
    echo "   - Run 'make validate-all' for comprehensive validation"
    exit 1
fi