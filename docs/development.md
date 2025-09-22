# Development Guide

This guide helps you set up a local development environment and understand the validation checks that prevent issues from reaching the GitHub workflow.

## Quick Start

1. **Initial Setup**

   ```bash
   make setup
   make install-hooks
   ```

2. **Development Workflow**
   ```bash
   # Make your changes
   make quick-fix      # Auto-fix common issues
   make pre-commit     # Run validation checks
   git add .
   git commit -m "feat: your changes"  # Pre-commit hook runs automatically
   ```

## Local Validation Checks

### Automated Checks (Pre-commit Hook)

When you commit code, the following checks run automatically:

1. **Go Code Formatting** - Ensures all Go files are formatted with `gofmt`
2. **Import Path Validation** - Checks for incorrect import paths
3. **Go Modules Validation** - Verifies `go.mod` and `go.sum` are valid and tidy
4. **Build Validation** - Ensures all packages build successfully
5. **OpenAPI Validation** - Validates the OpenAPI specification
6. **Linting** - Runs `golangci-lint` for code quality
7. **Unit Tests** - Runs all unit tests with race detection
8. **Test Coverage** - Checks test coverage meets minimum threshold
9. **Security Scan** - Runs `gosec` security analysis (if available)
10. **API Validation** - Validates API implementation against OpenAPI spec

### Manual Validation Commands

```bash
# Quick validation (runs in ~30 seconds)
make pre-commit

# Comprehensive validation (runs all possible checks)
make validate-comprehensive

# Individual checks
make fmt                    # Format code
make lint                   # Run linter
make test                   # Run unit tests
make test-coverage          # Run tests with coverage
make validate-openapi       # Validate OpenAPI spec
make validate-api           # Validate API implementation
make security-scan          # Run security analysis
```

### Auto-fix Common Issues

```bash
# Automatically fix formatting and common issues
make quick-fix

# Or run the script directly
./scripts/quick-fix.sh
```

## Git Hooks

### Installation

```bash
make install-hooks
```

This installs three Git hooks:

1. **pre-commit** - Runs validation checks before each commit
2. **commit-msg** - Validates commit message format (conventional commits)
3. **pre-push** - Runs additional checks before pushing to remote

### Commit Message Format

Use conventional commit format:

```
<type>[optional scope]: <description>

Examples:
feat: add password hashing endpoint
fix(api): resolve validation error handling
docs: update API documentation
test: add unit tests for crypto module
chore: update dependencies
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`, `revert`

### Bypassing Hooks (Not Recommended)

```bash
git commit --no-verify    # Skip pre-commit and commit-msg hooks
git push --no-verify      # Skip pre-push hook
```

## Development Tools

### Required Tools

- **Go 1.22+** - Programming language
- **golangci-lint** - Code linting
- **swagger-cli** - OpenAPI validation (optional but recommended)

### Optional Tools

- **gosec** - Security analysis
- **docker** - Container testing
- **hey** - Load testing

### Tool Installation

```bash
# Install all development tools
make install-tools

# Or install individually
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
npm install -g @apidevtools/swagger-cli
```

## IDE Integration

### VS Code

Add to `.vscode/settings.json`:

```json
{
  "go.formatTool": "gofmt",
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "go.testFlags": ["-v", "-race"],
  "go.coverOnSave": true,
  "go.coverageDecorator": {
    "type": "gutter"
  }
}
```

### GoLand/IntelliJ

1. Enable `gofmt` on save: Settings → Tools → File Watchers → Add Go fmt
2. Enable golangci-lint: Settings → Tools → External Tools → Add golangci-lint
3. Configure test runner with `-race` flag

## Troubleshooting

### Common Issues

1. **Import Path Errors**

   ```bash
   # Auto-fix incorrect import paths
   make quick-fix
   ```

2. **Formatting Issues**

   ```bash
   # Format all Go files
   make fmt
   ```

3. **Test Failures**

   ```bash
   # Run tests with verbose output
   go test -v ./...

   # Run specific test
   go test -v ./internal/modules/crypto -run TestHashService
   ```

4. **Coverage Below Threshold**

   ```bash
   # Generate coverage report
   make test-coverage
   open coverage.html  # View detailed coverage
   ```

5. **Linting Errors**

   ```bash
   # See detailed linting issues
   make lint

   # Auto-fix some issues
   golangci-lint run --fix
   ```

### Pre-commit Hook Issues

If pre-commit checks fail:

1. **Read the error messages** - They usually indicate exactly what's wrong
2. **Run quick-fix** - `make quick-fix` fixes common issues automatically
3. **Run individual checks** - Use specific make targets to isolate issues
4. **Check the logs** - Pre-commit hook shows detailed output

### Performance Tips

- **Parallel Testing**: Tests run with `-race` flag for concurrency safety
- **Caching**: Go modules and build cache speed up repeated runs
- **Incremental Checks**: Pre-commit only runs necessary validations

## CI/CD Integration

The local checks mirror the GitHub Actions workflow:

| Local Command           | GitHub Action Job |
| ----------------------- | ----------------- |
| `make fmt`              | lint-and-format   |
| `make lint`             | lint-and-format   |
| `make test`             | test              |
| `make validate-openapi` | validate-api      |
| `make validate-api`     | validate-api      |
| `make security-scan`    | security-scan     |
| `make docker-test`      | build-docker      |

Running `make pre-commit` locally ensures your code will pass the GitHub workflow.

## Best Practices

1. **Run pre-commit checks** before every commit
2. **Install Git hooks** for automatic validation
3. **Use conventional commits** for clear history
4. **Write tests** for new features
5. **Update documentation** when changing APIs
6. **Run comprehensive validation** before creating PRs

## Getting Help

- **Make targets**: Run `make help` to see all available commands
- **Script help**: Most scripts show usage when run with `--help`
- **Validation details**: Check `scripts/pre-commit-checks.sh` for specific checks
- **CI workflow**: See `.github/workflows/ci.yml` for complete pipeline
