# go53 Installation Guide

## Installation Methods

---

## 1. Podman (Quickest)

The fastest way to get go53 running — no installation required beyond pulling the image.

```bash
# Create a persistent volume for data
podman volume create go53_data

# Run go53
podman run -d \
  --name go53 \
  --restart unless-stopped \
  -p 53:2053/udp \
  -p 53:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  ghcr.io/tenforwardab/go53:latest
```

### Port mapping explained

| Host port | Container port | Purpose |
|-----------|---------------|---------|
| 53 (UDP/TCP) | 2053 | DNS queries |
| 8053 | 8053 | REST API |
| 53530 | 53530 | Cluster sync |

> **Note:** go53 listens on port 2053 inside the container to avoid requiring root. We map it to standard port 53 on the host.

### Manage the container

```bash
podman stop go53
podman start go53
podman restart go53
podman logs -f go53
```

### Use go53ctl from inside the container

```bash
podman exec go53 go53ctl --help
```

### Persistent data

Data is stored in the `go53_data` named volume and survives container restarts and upgrades.

```bash
# Check where data is stored on disk
podman volume inspect go53_data

# Upgrade to a new version
podman pull ghcr.io/tenforwardab/go53:latest
podman stop go53 && podman rm go53
podman run -d --name go53 --restart unless-stopped \
  -p 53:2053/udp -p 53:2053/tcp \
  -p 8053:8053/tcp -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  ghcr.io/tenforwardab/go53:latest
```

---

## 2. Podman Quadlet (Systemd Integration)

Quadlets let Podman containers run as systemd services without root. This is the recommended approach for a persistent server setup on Linux.

### Create the quadlet file

```bash
mkdir -p ~/.config/containers/systemd
```

Create `~/.config/containers/systemd/go53.container`:

```ini
[Unit]
Description=go53 DNS Server
After=network-online.target
Wants=network-online.target

[Container]
Image=ghcr.io/tenforwardab/go53:latest
ContainerName=go53

# Port mappings
PublishPort=53:2053/udp
PublishPort=53:2053/tcp
PublishPort=8053:8053/tcp
PublishPort=53530:53530/tcp

# Persistent data volume
Volume=go53_data.volume:/var/lib/go53

# Auto-update policy
AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
```

Create `~/.config/containers/systemd/go53_data.volume`:

```ini
[Volume]
```

### Enable and start

```bash
# Reload systemd to pick up the new unit
systemctl --user daemon-reload

# Start the service
systemctl --user start go53

# Enable auto-start on login
systemctl --user enable go53

# Check status
systemctl --user status go53

# View logs
journalctl --user -u go53 -f
```

### Auto-updates with Podman

Since we set `AutoUpdate=registry`, you can enable automatic image updates:

```bash
# Enable the auto-update timer
systemctl --user enable --now podman-auto-update.timer

# Or trigger a manual update
podman auto-update
```

### Lingering (run without being logged in)

To keep go53 running even when you are not logged in:

```bash
sudo loginctl enable-linger $USER
```

---

## 3. Install Script (Binary + Systemd)

Installs go53 as system binaries with a root systemd service. Best for dedicated servers.

```bash
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash
```

The script will:
- Automatically detect the latest version from GitHub
- Detect your OS and CPU architecture
- Download the appropriate binaries (`go53` and `go53ctl`)
- Create a system user `go53`
- Install and enable a systemd service

**Install a specific version:**

```bash
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash -s v0.77.1
```

### Service management

```bash
sudo systemctl start go53
sudo systemctl stop go53
sudo systemctl restart go53
sudo systemctl status go53
journalctl -u go53 -f
```

### Directory structure

| Path | Purpose |
|------|---------|
| `/usr/local/bin/go53` | Server binary |
| `/usr/local/bin/go53ctl` | CLI tool |
| `/etc/go53/` | Configuration |
| `/var/lib/go53/` | Data directory |
| `/etc/systemd/system/go53.service` | Systemd unit file |

---

## 4. Manual Binary Install

```bash
VERSION=v0.77.1
PLATFORM=linux_amd64   # or linux_arm64, darwin_amd64, darwin_arm64

wget https://github.com/TenforwardAB/go53/releases/download/${VERSION}/go53_${VERSION#v}_${PLATFORM}.tar.gz
tar -xzf go53_*_${PLATFORM}.tar.gz

sudo install -m 755 go53/go53 /usr/local/bin/
sudo install -m 755 go53/go53ctl /usr/local/bin/
```

---

## 5. From Source

```bash
git clone https://github.com/TenforwardAB/go53.git
cd go53
make build

sudo install -m 755 go53 /usr/local/bin/
sudo install -m 755 go53ctl /usr/local/bin/
```

---

## Verification

```bash
# Test DNS (binary install)
dig @localhost example.com

# Test API
curl http://localhost:8053/

# Check go53ctl (container)
podman exec go53 go53ctl --help
```

---

## Uninstallation

### Podman

```bash
podman stop go53 && podman rm go53
podman volume rm go53_data
podman rmi ghcr.io/tenforwardab/go53:latest
```

### Quadlet

```bash
systemctl --user stop go53
systemctl --user disable go53
rm ~/.config/containers/systemd/go53.container
rm ~/.config/containers/systemd/go53_data.volume
systemctl --user daemon-reload
```

### Binary install

```bash
sudo systemctl stop go53 && sudo systemctl disable go53
sudo rm /etc/systemd/system/go53.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/go53 /usr/local/bin/go53ctl
sudo userdel -r go53
sudo rm -rf /etc/go53 /var/lib/go53
```

---

## Support

- GitHub Issues: https://github.com/TenforwardAB/go53/issues
- Documentation: https://github.com/TenforwardAB/go53/tree/main/docs
