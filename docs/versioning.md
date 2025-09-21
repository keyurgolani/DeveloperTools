# Version Management

This project uses a centralized versioning system to ensure consistency across all components.

## Overview

The version is managed from a single source of truth and automatically propagated to all relevant files:

- **Central Version File**: `VERSION` - Contains the current version number
- **Build-time Injection**: Version is injected into Go binaries during build
- **Automatic Synchronization**: Script updates all files that reference the version

## Files That Use Version Information

1. **Go Application** (`internal/version/version.go`)
   - Version injected at build time via ldflags
   - Accessible via `version.Get()` function

2. **OpenAPI Specification** (`api/openapi.yml`)
   - Version field in the info section

3. **Docker Image** (`Dockerfile`)
   - Build argument and image label

4. **Kubernetes Deployment** (`deployments/k8s-deployment.yaml`)
   - Version labels for pods and deployment

5. **Node.js MCP Bridge** (`mcp-bridge/package.json`, `mcp-bridge/mcp-bridge.js`)
   - Package version and runtime version info

## Usage

### Check Current Version

```bash
make version
```

### Update Version

```bash
# Update to a new version (follows semantic versioning)
make set-version VERSION=1.2.3

# Or run the script directly
./scripts/sync-version.sh 1.2.3
```

### Build with Version

```bash
# Build Go binary with version injection
make build

# Build Docker image with version
make docker-build
```

## Version Format

The project follows [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., 1.0.0)
- **Pre-release**: MAJOR.MINOR.PATCH-alpha.1
- **Build metadata**: MAJOR.MINOR.PATCH+20231201

## Automated Synchronization

The `scripts/sync-version.sh` script automatically updates:

- ✅ `VERSION` file (if version provided as argument)
- ✅ `api/openapi.yml` - OpenAPI version field
- ✅ `deployments/k8s-deployment.yaml` - Kubernetes labels
- ✅ `mcp-bridge/package.json` - Node.js package version
- ✅ `mcp-bridge/mcp-bridge.js` - Runtime version info
- ⚠️ `mcp-bridge/package-lock.json` - Requires `npm install` to regenerate

## Build-time Information

In addition to the version, the following information is injected at build time:

- **Version**: From `VERSION` file
- **BuildDate**: UTC timestamp when binary was built
- **GitCommit**: Short Git commit hash

Access this information in Go code:

```go
import "dev-utilities/internal/version"

info := version.Get()
fmt.Printf("Version: %s\n", info.Version)
fmt.Printf("Built: %s\n", info.BuildDate)
fmt.Printf("Commit: %s\n", info.GitCommit)
```

## CI/CD Integration

The versioning system integrates with CI/CD pipelines:

1. **Development**: Uses "dev" as default version
2. **Builds**: Automatically inject version from `VERSION` file
3. **Releases**: Update version and tag releases
4. **Docker**: Images tagged with both "latest" and version number

## Best Practices

1. **Always use the sync script** when updating versions
2. **Follow semantic versioning** for predictable releases
3. **Test after version updates** to ensure all components work
4. **Commit version changes** as a single atomic commit
5. **Tag releases** in Git with the version number

## Troubleshooting

### Version Mismatch

If you see different versions in different files:

```bash
# Re-sync all files to current VERSION
./scripts/sync-version.sh

# Or set a specific version
./scripts/sync-version.sh 1.2.3
```

### Build Issues

If builds fail with version-related errors:

```bash
# Ensure VERSION file exists
echo "1.0.0" > VERSION

# Clean and rebuild
make clean build
```

### Node.js Package Issues

After version updates, regenerate package-lock.json:

```bash
cd mcp-bridge
npm install
```

## Migration from Old System

If migrating from hardcoded versions:

1. Create `VERSION` file with current version
2. Run sync script: `./scripts/sync-version.sh`
3. Update build processes to use new Makefile targets
4. Test all components to ensure version injection works
5. Remove any remaining hardcoded version references