---
title: "Releases"
linkTitle: "Releases"
weight: 14
description: "go53 release process and notes."
---

# Release Process for go53

## Automated Releases with GitHub Actions

### How It Works
When you push a git tag starting with `v` (e.g., `v0.77.0`), GitHub Actions automatically:
1. **GoReleaser** builds binaries for all platforms (Linux, macOS, Windows)
2. Both applications are bundled: `go53` (server) and `go53ctl` (CLI tool)
3. Binaries are published on GitHub Releases with checksums

### Release Process

#### 1. Create Version
```bash
./bump_version.sh
# Answer with the new version, e.g., 0.77.0
```

Or manually:
```bash
echo "0.77.0" > VERSION
```

#### 2. Create Git Tag
```bash
git tag -a v0.77.0 -m "Release version 0.77.0"
git push origin v0.77.0
```

Or via `bump_version.sh` (which does everything automatically).

#### 3. GitHub Actions Runs Automatically
- GitHub Actions takes over and builds everything
- You can monitor progress in [Actions](https://github.com/TenforwardAB/go53/actions)
- Binaries are published on the [Releases page](https://github.com/TenforwardAB/go53/releases)

### Download Binaries

#### One-liner Installation (Linux/macOS)
The easiest way to install go53 with systemd service support:
```bash
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash
```

Or with a specific version:
```bash
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash -s v0.77.0
```

#### Manual Installation
After release, binaries are available for direct download:
```bash
# Linux x86_64
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_linux_amd64.tar.gz

# macOS arm64 (Apple Silicon)
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_darwin_arm64.tar.gz

# Windows x86_64
wget https://github.com/TenforwardAB/go53/releases/download/v0.77.0/go53_0.77.0_windows_amd64.zip
```

Extract and install manually:
```bash
tar -xzf go53_0.77.0_linux_amd64.tar.gz
sudo install -m 755 go53/go53 /usr/local/bin/
sudo install -m 755 go53/go53ctl /usr/local/bin/
```

### Local Testing Before Release
```bash
# Build locally
make build

# Test binaries
./go53 --help
./go53ctl --help
```

### Configuration
- **`.goreleaser.yml`** - Defines which binaries are built and for which platforms
- **`.github/workflows/release.yml`** - GitHub Actions workflow triggered on tags

### Supported Platforms
- **Linux**: amd64, arm64
- **macOS**: amd64, arm64 (Intel & Apple Silicon)
- **Windows**: amd64, arm64

### Systemd Service (Linux)

The installation script automatically sets up a systemd service. After installation:

```bash
# Start the service
sudo systemctl start go53

# Enable auto-start on boot
sudo systemctl enable go53

# Check service status
sudo systemctl status go53

# View logs
journalctl -u go53 -f

# Stop the service
sudo systemctl stop go53

# Restart the service
sudo systemctl restart go53
```

#### Service Configuration
- **User**: `go53` (created automatically)
- **Config Directory**: `/etc/go53`
- **Data Directory**: `/var/lib/go53`
- **Service File**: `/etc/systemd/system/go53.service`

Edit the service file to customize:
```bash
sudo systemctl edit go53
```

#### View Service Logs
```bash
# Last 50 lines
journalctl -u go53 -n 50

# Real-time logs
journalctl -u go53 -f

# Today's logs
journalctl -u go53 --since today
```

### Checksums
Each release includes `checksums.txt` to verify file integrity:
```bash
sha256sum -c checksums.txt
```
