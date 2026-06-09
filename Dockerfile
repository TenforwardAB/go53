# Multi-stage build for optimized Alpine image
# Stage 1: Build both go53 server and go53ctl binaries
FROM docker.io/library/golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build go53 server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /tmp/go53 ./cmd/server

# Build go53ctl CLI tool
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /tmp/go53ctl ./cmd/go53ctl

# Stage 2: Runtime image
FROM docker.io/library/alpine:latest

LABEL maintainer="TenforwardAB <info@tenforward.se>"
LABEL description="go53 - Distributed DNS Server"
LABEL org.opencontainers.image.source="https://github.com/TenforwardAB/go53"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create go53 user and directories
RUN addgroup -g 1000 go53 && \
    adduser -D -u 1000 -G go53 go53 && \
    mkdir -p /var/lib/go53 /etc/go53 /data && \
    chown -R go53:go53 /var/lib/go53 /etc/go53 /data && \
    chmod -R 755 /var/lib/go53 /etc/go53 /data

# Copy binaries from builder
COPY --from=builder --chown=go53:go53 /tmp/go53 /usr/local/bin/go53
COPY --from=builder --chown=go53:go53 /tmp/go53ctl /usr/local/bin/go53ctl

# Set executable permissions
RUN chmod +x /usr/local/bin/go53 /usr/local/bin/go53ctl

# Set working directory
WORKDIR /var/lib/go53

# Expose ports:
# - 53: DNS (UDP/TCP)
# - 2053: DNS TCP (alternative port)
# - 8053: REST API
# - 53530: Cluster synchronization
EXPOSE 53/udp 53/tcp 2053/tcp 8053/tcp 53530/tcp

# Health check - verify API is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8053/health || exit 1

# Run as non-root user
USER go53

# Default command
CMD ["/usr/local/bin/go53"]
