# Deployment Guide

This guide covers various deployment options for the Developer Utilities MCP Server.

## Table of Contents

- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Management](#configuration-management)
- [Security Considerations](#security-considerations)
- [Monitoring and Observability](#monitoring-and-observability)
- [Troubleshooting](#troubleshooting)

## Docker Deployment

### Basic Docker Run

```bash
# Build the image
docker build -t dev-utilities .

# Run with default configuration
docker run -p 8080:8080 dev-utilities

# Run with custom configuration
docker run -p 8080:8080 \
  -e LOG_LEVEL=debug \
  -e AUTH_METHOD=api_key \
  -e AUTH_API_KEYS=your-api-key-1,your-api-key-2 \
  dev-utilities
```

### Docker Compose

Use the provided `docker-compose.yml` for easy development:

```bash
# Start with default configuration
docker-compose up

# Start with Redis rate limiting
docker-compose --profile redis-example up
```

### Production Docker Configuration

```bash
docker run -d \
  --name dev-utilities \
  --restart unless-stopped \
  -p 8080:8080 \
  -e LOG_LEVEL=info \
  -e AUTH_METHOD=api_key \
  -e AUTH_API_KEYS=your-secure-api-keys \
  -e RATE_LIMIT_STORE=redis \
  -e RATE_LIMIT_REDIS_URL=redis://your-redis:6379 \
  -e GIN_MODE=release \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=100m \
  -v /path/to/secrets:/etc/secrets:ro \
  dev-utilities
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured
- Secrets created for API keys and Redis URL

### Create Secrets

```bash
# Create API keys secret
kubectl create secret generic dev-utilities-secrets \
  --from-literal=api-keys="key1,key2,key3" \
  --from-literal=redis-url="redis://redis-service:6379"
```

### Deploy

```bash
# Apply the deployment
kubectl apply -f k8s-deployment.yaml

# Check deployment status
kubectl get pods -l app=dev-utilities
kubectl get svc dev-utilities
```

### Scaling

```bash
# Scale the deployment
kubectl scale deployment dev-utilities --replicas=5

# Enable horizontal pod autoscaling
kubectl autoscale deployment dev-utilities \
  --cpu-percent=70 \
  --min=3 \
  --max=10
```

## Configuration Management

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `8080` | HTTP server port |
| `SERVER_TLS_ENABLED` | `false` | Enable TLS (requires cert files) |
| `AUTH_METHOD` | `none` | Authentication method (`none`, `api_key`, `jwt`) |
| `AUTH_API_KEYS` | `""` | Comma-separated API keys |
| `AUTH_JWT_SECRET` | `""` | JWT signing secret |
| `AUTH_JWT_ISSUER` | `""` | Expected JWT issuer |
| `AUTH_JWT_AUDIENCE` | `""` | Expected JWT audience |
| `RATE_LIMIT_STORE` | `memory` | Rate limit store (`memory`, `redis`) |
| `RATE_LIMIT_REDIS_URL` | `""` | Redis connection URL |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `ARGON_MEMORY` | `65536` | Argon2 memory in KB |
| `ARGON_ITERATIONS` | `3` | Argon2 iterations |
| `ARGON_PARALLELISM` | `4` | Argon2 parallelism |
| `SECRETS_MOUNT_PATH` | `/etc/secrets` | Path for mounted secrets |

### Configuration File

Create a `config.json` file:

```json
{
  "server": {
    "port": 8080,
    "tlsEnabled": false
  },
  "auth": {
    "method": "api_key",
    "apiKeys": ["key1", "key2"]
  },
  "log": {
    "level": "info"
  },
  "crypto": {
    "argonMemory": 65536,
    "argonIterations": 3,
    "argonParallelism": 4
  }
}
```

Load with:
```bash
./server --config=/path/to/config.json
```

### Mounted Secrets

For production deployments, use mounted secrets:

```bash
# Create secret files
echo "your-jwt-secret" > /etc/secrets/jwt-secret
echo "key1,key2,key3" > /etc/secrets/api-keys
echo "redis://redis:6379" > /etc/secrets/redis-url

# Set environment variable
export SECRETS_MOUNT_PATH=/etc/secrets
```

## Security Considerations

### Container Security

- Runs as non-root user (UID 65534)
- Read-only root filesystem
- No new privileges
- Minimal attack surface with distroless base image
- Resource limits enforced

### Network Security

- SSRF protection for external requests
- Input validation and sanitization
- Rate limiting to prevent abuse
- Network policies in Kubernetes

### Secrets Management

- Never log sensitive data
- Use mounted secrets in production
- Rotate API keys regularly
- Use strong JWT secrets

### Authentication

```bash
# API Key authentication
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/crypto/hash

# JWT authentication
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8080/api/v1/crypto/hash
```

## Monitoring and Observability

### Health Checks

- **Liveness**: `GET /health/live` - Basic server responsiveness
- **Readiness**: `GET /health/ready` - Service readiness
- **General**: `GET /health` - Overall health status

### Metrics

Prometheus metrics available at `/metrics`:

- HTTP request metrics (count, duration, status codes)
- Business metrics per module
- Go runtime metrics
- Custom application metrics

### Logging

Structured JSON logging with:
- Request ID tracing
- Sensitive data protection
- Configurable log levels
- Request/response logging

### Tracing

OpenTelemetry support with:
- Jaeger exporter
- OTLP exporter
- Configurable sampling rates

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check logs
docker logs <container-id>

# Common causes:
# - Invalid configuration
# - Missing required environment variables
# - Port already in use
```

#### Health Check Failures

```bash
# Test health check manually
docker exec <container-id> /server --health-check

# Check if server is listening
docker exec <container-id> netstat -tlnp
```

#### High Memory Usage

```bash
# Check memory usage
docker stats <container-id>

# Adjust Argon2 parameters
-e ARGON_MEMORY=32768  # Reduce from default 65536
```

#### Rate Limiting Issues

```bash
# Check Redis connectivity
docker exec <container-id> ping redis-host

# Verify Redis URL format
redis://username:password@host:port/database
```

### Debug Mode

Enable debug logging:

```bash
docker run -e LOG_LEVEL=debug dev-utilities
```

### Performance Tuning

#### Resource Limits

```yaml
resources:
  requests:
    memory: "64Mi"
    cpu: "50m"
  limits:
    memory: "256Mi"
    cpu: "200m"
```

#### Argon2 Tuning

Balance security vs performance:

```bash
# High security (slower)
-e ARGON_MEMORY=131072 -e ARGON_ITERATIONS=4

# Balanced (default)
-e ARGON_MEMORY=65536 -e ARGON_ITERATIONS=3

# Fast (less secure)
-e ARGON_MEMORY=32768 -e ARGON_ITERATIONS=2
```

### Support

For issues and support:

1. Check the logs for error messages
2. Verify configuration values
3. Test with minimal configuration
4. Check network connectivity
5. Review resource usage

## Production Checklist

- [ ] Use specific image tags, not `latest`
- [ ] Configure resource limits
- [ ] Set up monitoring and alerting
- [ ] Use mounted secrets for sensitive data
- [ ] Enable TLS in production
- [ ] Configure proper logging
- [ ] Set up backup for Redis (if used)
- [ ] Test disaster recovery procedures
- [ ] Configure network policies
- [ ] Set up horizontal pod autoscaling
- [ ] Monitor security vulnerabilities
- [ ] Regular security updates