# go53 Installation Guide

## Quick Start (Linux/macOS)

The easiest way to install go53 and set up a systemd service:

```bash
curl -fsSL https://github.com/TenforwardAB/go53/releases/download/latest/install.sh | sudo bash
```

This script will:
- Detect your OS and CPU architecture
- Download the appropriate binaries
- Install both `go53` (server) and `go53ctl` (CLI tool)
- Create a system user (`go53`)
- Set up systemd service for automatic startup (Linux only)

## Installation Methods

### 1. Automatic Installation (Recommended)

The installation script handles everything automatically:

```bash
# Install latest version
curl -fsSL https://github.com/TenforwardAB/go53/releases/download/v0.77.0/install.sh | sudo bash

# Install specific version
curl -fsSL https://github.com/TenforwardAB/go53/releases/download/v0.76.0/install.sh | sudo bash -s v0.76.0
```

### 2. Manual Installation

If you prefer to install manually:

```bash
# 1. Download binaries for your platform
VERSION=v0.77.0
PLATFORM=linux_amd64  # Change based on your OS/arch
wget https://github.com/TenforwardAB/go53/releases/download/${VERSION}/go53_${VERSION#v}_${PLATFORM}.tar.gz

# 2. Extract
tar -xzf go53_*_${PLATFORM}.tar.gz

# 3. Install binaries
sudo install -m 755 go53/go53 /usr/local/bin/
sudo install -m 755 go53/go53ctl /usr/local/bin/

# 4. Verify
go53 --version
go53ctl --version
```

### 3. From Source

```bash
git clone https://github.com/TenforwardAB/go53.git
cd go53

# Build binaries
make build

# Install
sudo install -m 755 go53 /usr/local/bin/
sudo install -m 755 go53ctl /usr/local/bin/
```

## Post-Installation Setup

### Linux with Systemd

If you used the automatic installer, systemd is already configured. If not:

```bash
# 1. Create system user
sudo useradd -r -s /bin/false -d /var/lib/go53 -m go53

# 2. Create directories
sudo mkdir -p /etc/go53 /var/lib/go53
sudo chown go53:go53 /etc/go53 /var/lib/go53

# 3. Install service file
sudo curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/go53.service \
  -o /etc/systemd/system/go53.service
sudo systemctl daemon-reload

# 4. Enable and start
sudo systemctl enable go53
sudo systemctl start go53
```

### macOS

go53 can be run manually or via a launch agent:

```bash
# Run in foreground
go53

# Run in background
nohup go53 > /var/log/go53.log 2>&1 &
```

## Service Management (Linux)

```bash
# Start service
sudo systemctl start go53

# Stop service
sudo systemctl stop go53

# Restart service
sudo systemctl restart go53

# Check status
sudo systemctl status go53

# Enable auto-start on boot
sudo systemctl enable go53

# Disable auto-start
sudo systemctl disable go53

# View logs (last 50 lines)
journalctl -u go53 -n 50

# Follow logs in real-time
journalctl -u go53 -f

# View logs from today
journalctl -u go53 --since today
```

## Configuration

### Directory Structure
- **Binaries**: `/usr/local/bin/go53`, `/usr/local/bin/go53ctl`
- **Configuration**: `/etc/go53/`
- **Data**: `/var/lib/go53/`
- **Service**: `/etc/systemd/system/go53.service`

### Configuration Files
Create `/etc/go53/config.yaml` to customize go53 behavior. See documentation for available options.

## Verification

```bash
# Check if binaries are accessible
which go53
which go53ctl

# Check service status (Linux)
sudo systemctl status go53

# View recent logs (Linux)
journalctl -u go53 -n 20

# Test DNS connectivity
dig @localhost example.com
```

## Troubleshooting

### Service won't start
```bash
# Check service status
sudo systemctl status go53

# View error logs
journalctl -u go53 -n 100

# Run go53 directly to see errors
sudo -u go53 /usr/local/bin/go53
```

### Permission denied errors
```bash
# Fix directory permissions
sudo chown -R go53:go53 /var/lib/go53
sudo chmod -R 755 /var/lib/go53

# Fix configuration permissions
sudo chown -R go53:go53 /etc/go53
sudo chmod -R 755 /etc/go53
```

### Binaries not found
```bash
# Verify binaries are installed
ls -la /usr/local/bin/go53*

# Ensure /usr/local/bin is in PATH
echo $PATH

# If not, add to ~/.bashrc or ~/.zshrc
export PATH="/usr/local/bin:$PATH"
```

## Uninstallation

```bash
# Stop and disable service (Linux)
sudo systemctl stop go53
sudo systemctl disable go53
sudo rm /etc/systemd/system/go53.service
sudo systemctl daemon-reload

# Remove binaries
sudo rm /usr/local/bin/go53 /usr/local/bin/go53ctl

# Remove system user and directories (optional)
sudo userdel -r go53
sudo rm -rf /etc/go53 /var/lib/go53
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/TenforwardAB/go53/issues
- Documentation: https://github.com/TenforwardAB/go53/tree/main/docs
