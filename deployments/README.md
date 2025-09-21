# Deployment Configurations

This directory contains deployment configurations and orchestration files for the Developer Utilities MCP Server.

## Files

### `docker-compose.yml`
Docker Compose configuration for local development and testing:
- Main application service with configurable profiles
- Optional Redis service for rate limiting (use `--profile redis-example`)
- Network configuration with isolated bridge network
- Health checks and security settings (non-root, read-only filesystem)
- Two service variants: basic (memory rate limiting) and Redis-enabled

### `k8s-deployment.yaml`
Production-ready Kubernetes deployment manifests including:
- **Deployment**: 3-replica configuration with security contexts
- **Service**: ClusterIP service exposing port 80→8080
- **Secret**: Base64-encoded API keys and Redis URL (update before use!)
- **NetworkPolicy**: Ingress/egress rules for security isolation
- **PodDisruptionBudget**: Ensures minimum 2 replicas during updates

**Note**: The Secret in `k8s-deployment.yaml` contains example values. Replace with your actual base64-encoded secrets before deploying to production.

## Usage

### Docker Compose

```bash
# Start the application
docker-compose -f deployments/docker-compose.yml up

# Start with Redis rate limiting
docker-compose -f deployments/docker-compose.yml --profile redis-example up

# Run in background
docker-compose -f deployments/docker-compose.yml up -d
```

### Kubernetes

```bash
# Create required secrets first
kubectl create secret generic dev-utilities-secrets \
  --from-literal=api-keys="your-api-key-1,your-api-key-2" \
  --from-literal=redis-url="redis://redis-service:6379"

# Deploy to Kubernetes
kubectl apply -f deployments/k8s-deployment.yaml

# Check deployment status
kubectl get pods -l app=dev-utilities
kubectl get services
```

## Configuration

Both deployment methods support environment variable configuration:
- `SERVER_PORT` - HTTP server port
- `AUTH_METHOD` - Authentication method
- `LOG_LEVEL` - Logging level
- `RATE_LIMIT_STORE` - Rate limiting backend
- And more (see main README.md)

## Security

Both configurations include security best practices:
- Non-root execution
- Read-only filesystems
- Security contexts
- Network policies (Kubernetes)
- Resource limits