# Running go53 in Containers

This guide covers running go53 as a container using Docker, Docker Compose, or Podman.

## Quick Start

### Option 1: Using Pre-built Image from GitHub Container Registry

Pull and run the latest published image:

```bash
# Pull the image
podman pull ghcr.io/TenforwardAB/go53:latest

# Run with persistent storage
podman volume create go53_data
podman run -d \
  --name go53 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 2053:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  ghcr.io/TenforwardAB/go53:latest
```

### Option 2: Using Docker Compose (Local Build)

The easiest way to get started with persistent storage:

```bash
docker-compose up -d
```

This will:
- Build the go53 container image from the Dockerfile
- Start the go53 service
- Create a named volume for persistent data storage
- Expose all required ports
- Enable health checks

## Container Images

### Published Images

Container images are automatically built and published to GitHub Container Registry on each release:

- **Latest**: `ghcr.io/TenforwardAB/go53:latest`
- **Versioned**: `ghcr.io/TenforwardAB/go53:v0.77.0`
- **Multi-platform**: Supports `linux/amd64` and `linux/arm64`

Pull from GHCR:
```bash
podman pull ghcr.io/TenforwardAB/go53:latest
docker pull ghcr.io/TenforwardAB/go53:latest
```

### Image Details

The container uses a multi-stage Alpine build:
- **Base**: Alpine Linux (minimal, ~70MB)
- **Builder**: golang:1.23-alpine (for compilation)
- **Includes**: go53 server + go53ctl CLI tool
- **User**: Non-root `go53` user for security
- **Health checks**: Built-in HTTP health endpoint
- **Platforms**: linux/amd64, linux/arm64

### Exposed Ports

| Port  | Protocol | Purpose | Notes |
|-------|----------|---------|-------|
| 53    | UDP/TCP  | DNS queries | Standard DNS port (mapped from 2053 inside container) |
| 2053  | TCP      | DNS (inside container) | Internal port that go53 server listens on |
| 8053  | TCP      | REST API | Management and status API |
| 53530 | TCP      | Cluster synchronization | Node-to-node cluster communication |

**Note**: Inside the container, go53 listens on port 2053 (instead of standard 53) to avoid requiring root privileges. The port mapping `53:2053` exposes it as standard DNS port 53 to external clients.

## Running with Podman

### Build the Image

```bash
podman build -t go53:latest .
```

### Basic Run (No Persistent Data)

```bash
podman run -d \
  --name go53 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 2053:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  localhost/go53:latest
```

### Run with Persistent Data Volume

```bash
# Create a named volume
podman volume create go53_data

# Run with mounted volume
podman run -d \
  --name go53 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 2053:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest
```

### Run with Host Directory (Development)

Mount a local directory for data and configuration:

```bash
mkdir -p ./data ./config

podman run -d \
  --name go53 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 2053:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v ./data:/var/lib/go53 \
  -v ./config:/etc/go53:ro \
  localhost/go53:latest
```

### Persistent Data Management with Podman

#### Using Named Volumes (Recommended)

Named volumes are easier to manage and work across restarts:

```bash
# Create volume
podman volume create go53_data

# Run container with volume
podman run -d \
  --name go53 \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest

# List volumes
podman volume ls

# Inspect volume
podman volume inspect go53_data

# Remove volume (after stopping container)
podman stop go53
podman rm go53
podman volume rm go53_data
```

#### Using Host Directories

For development or custom storage paths:

```bash
# Create directories
mkdir -p /opt/go53/data /opt/go53/config

# Run with host mount
podman run -d \
  --name go53 \
  -v /opt/go53/data:/var/lib/go53 \
  -v /opt/go53/config:/etc/go53:ro \
  localhost/go53:latest

# Data persists in /opt/go53/data
ls -la /opt/go53/data/
```

## Container Management

### View Logs

```bash
# Docker Compose
docker-compose logs -f go53

# Podman
podman logs -f go53
```

### Check Status

```bash
# Docker Compose
docker-compose ps

# Podman
podman ps -a
podman inspect go53
```

### Access CLI Tool

The container includes `go53ctl`. Access it using:

```bash
# Docker Compose
docker-compose exec go53 go53ctl --help

# Podman
podman exec go53 go53ctl --help
```

### Stop/Restart Container

```bash
# Docker Compose
docker-compose stop
docker-compose start
docker-compose restart

# Podman
podman stop go53
podman start go53
podman restart go53
```

### Remove Container

```bash
# Docker Compose
docker-compose down

# Podman
podman stop go53
podman rm go53
```

## Data Persistence

### Docker Compose Volumes

Data is automatically persisted in the `go53_data` named volume:

```bash
# View volume location
docker volume inspect go53_data

# Remove volume (keeps data on disk but removes Docker reference)
docker volume rm go53_data

# Clean everything (removes volume data)
docker-compose down -v
```

### Podman Volume Locations

Podman stores volumes in different locations based on the driver:

```bash
# Default location (rootful)
/var/lib/containers/storage/volumes/

# User-level (rootless)
~/.local/share/containers/storage/volumes/

# View volume path
podman volume inspect go53_data --format '{{ .Mountpoint }}'
```

### Backup Data

```bash
# Backup volume to tar
docker run --rm \
  -v go53_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/go53_backup.tar.gz -C /data .

# Restore from backup
docker run --rm \
  -v go53_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/go53_backup.tar.gz -C /data

# With Podman
podman run --rm \
  -v go53_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/go53_backup.tar.gz -C /data .
```

## Network Configuration

### DNS Queries from Host

Query the container's DNS server:

```bash
# Use container as DNS resolver
dig @localhost example.com

# Specify port if using non-standard port
dig @localhost -p 2053 example.com
```

### Multi-Host Setup

For cluster synchronization across hosts:

```bash
# Node 1
podman run -d \
  --name go53-node1 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  -e CLUSTER_NODE=node1 \
  localhost/go53:latest

# Node 2 (configure to sync with Node 1)
podman run -d \
  --name go53-node2 \
  -p 54:53/udp \
  -p 54:53/tcp \
  -p 8054:8053/tcp \
  -p 53531:53530/tcp \
  -v go53_data_2:/var/lib/go53 \
  -e CLUSTER_PEER=node1:53530 \
  localhost/go53:latest
```

## Troubleshooting

### Container won't start

```bash
# Check logs
podman logs go53

# Inspect container
podman inspect go53

# Run interactively to debug
podman run -it \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest /bin/sh
```

### DNS not responding

```bash
# Check if port is exposed
podman port go53

# Check DNS connectivity from host
dig @localhost example.com

# Check from inside container
podman exec go53 go53ctl status
```

### Data not persisting

```bash
# Check volume
podman volume inspect go53_data

# Verify mount point
podman inspect go53 --format '{{ json .Mounts }}' | jq

# Check permissions
podman exec go53 ls -la /var/lib/go53
```

## Production Considerations

### Resource Limits

```bash
podman run -d \
  --memory="512m" \
  --cpus="2" \
  --name go53 \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest
```

### Security

```bash
# Run with read-only root filesystem
podman run -d \
  --read-only \
  --tmpfs /tmp \
  -v go53_data:/var/lib/go53 \
  --security-opt no-new-privileges \
  localhost/go53:latest
```

### Restart Policy

```bash
# Always restart on failure
podman run -d \
  --restart=always \
  --name go53 \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest

# Restart with max retry limit
podman run -d \
  --restart=on-failure:5 \
  --name go53 \
  -v go53_data:/var/lib/go53 \
  localhost/go53:latest
```

## Docker Compose Advanced

### Custom Networks

```yaml
services:
  go53:
    networks:
      - go53-network
    ports:
      - "53:53/udp"
      - "8053:8053"

  # Other services that need to query go53
  resolver:
    image: alpine:latest
    networks:
      - go53-network
    depends_on:
      - go53

networks:
  go53-network:
    driver: bridge
```

### Environment-Specific Configuration

```bash
# Development
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up
```

## Getting Help

For more information:
- [Podman Documentation](https://docs.podman.io/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [go53 GitHub Repository](https://github.com/TenforwardAB/go53)
