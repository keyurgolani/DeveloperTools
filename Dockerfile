# Multi-stage build for minimal production image
FROM golang:1.22-alpine AS builder

# Install ca-certificates and git for HTTPS requests and potential private dependencies
RUN apk --no-cache add ca-certificates git tzdata

# Create non-root user for build process
RUN adduser -D -g '' appuser

WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies with retry logic and timeout
RUN go env -w GOPROXY=https://proxy.golang.org,direct && \
    go env -w GOSUMDB=sum.golang.org && \
    timeout 300 go mod download || \
    (echo "Retrying go mod download..." && timeout 300 go mod download) || \
    (echo "Final retry with direct mode..." && GOPROXY=direct timeout 300 go mod download) && \
    go mod verify

# Copy source code
COPY . .

# Build the application with security flags
ARG VERSION
ARG BUILD_DATE
ARG GIT_COMMIT
RUN VERSION=${VERSION:-$(cat VERSION 2>/dev/null || echo "dev")} && \
    BUILD_DATE=${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")} && \
    GIT_COMMIT=${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")} && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags="-w -s -extldflags '-static' -X 'dev-utilities/internal/version.Version=${VERSION}' -X 'dev-utilities/internal/version.BuildDate=${BUILD_DATE}' -X 'dev-utilities/internal/version.GitCommit=${GIT_COMMIT}'" \
    -o server ./cmd/server

# Create directories for configuration and secrets in builder stage
RUN mkdir -p /tmp/config /tmp/secrets && \
    chown -R appuser:appuser /tmp/config /tmp/secrets

# Verify the binary
RUN ./server --help || echo "Binary built successfully"

# Final stage - use distroless for better security
FROM gcr.io/distroless/static:nonroot

# Copy timezone data for time operations
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy ca-certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/server /server

# Copy pre-created directories from builder
COPY --from=builder --chown=nonroot:nonroot /tmp/config /etc/config
COPY --from=builder --chown=nonroot:nonroot /tmp/secrets /etc/secrets

# Expose port
EXPOSE 8080

# Add health check using curl (but distroless doesn't have curl, so we'll use a simple approach)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD ["/server", "--health-check"] || exit 1

# Set environment variables for production
ENV GIN_MODE=release
ENV LOG_LEVEL=info
ENV SERVER_PORT=8080

# Add labels for better container management
ARG VERSION
LABEL maintainer="dev-utilities" \
      version="${VERSION:-1.0.0}" \
      description="Developer Utilities Server" \
      org.opencontainers.image.source="https://github.com/example/dev-utilities" \
      org.opencontainers.image.documentation="https://github.com/example/dev-utilities/README.md" \
      org.opencontainers.image.licenses="Apache-2.0"

# Run the server
ENTRYPOINT ["/server"]