#!/bin/bash
#
# go53 Installation Script
# Downloads and installs go53 server and go53ctl
# Sets up systemd service for automatic startup
#
# Usage: curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash
# Or:    bash <(curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh)
# With specific version: ... | sudo bash -s v0.77.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="${1:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/go53"
DATA_DIR="/var/lib/go53"
USER="go53"
GROUP="go53"
GITHUB_REPO="TenforwardAB/go53"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Detect OS and architecture
detect_platform() {
    local os
    local arch

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$arch" in
        x86_64)
            arch="amd64"
            ;;
        aarch64)
            arch="arm64"
            ;;
        arm64)
            arch="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    case "$os" in
        linux)
            os="linux"
            ;;
        darwin)
            os="darwin"
            ;;
        *)
            log_error "Unsupported OS: $os"
            return 1
            ;;
    esac

    echo "${os}_${arch}"
}

# Get latest release version from GitHub
get_latest_version() {
    local latest
    log_info "Fetching latest release from GitHub API..."

    latest=$(curl -s "${GITHUB_API}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

    if [ -z "$latest" ]; then
        log_error "Failed to fetch latest version from GitHub"
        log_error "Check: ${GITHUB_API}/releases/latest"
        return 1
    fi

    echo "$latest"
}

# Download and install binaries
install_binaries() {
    local platform=$1
    local version=$2
    local temp_dir

    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    log_info "Downloading go53 $version for $platform..."

    local archive_name="go53_${version#v}_${platform}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${archive_name}"

    if ! curl -sL -f "$download_url" -o "$temp_dir/$archive_name"; then
        log_error "Failed to download $archive_name from $download_url"
        return 1
    fi

    log_info "Extracting binaries..."
    tar -xzf "$temp_dir/$archive_name" -C "$temp_dir"

    # Find and install binaries
    local bin_count=0
    for binary in go53 go53ctl; do
        if [ -f "$temp_dir/go53/$binary" ]; then
            log_info "Installing $binary to $INSTALL_DIR..."
            sudo install -m 755 "$temp_dir/go53/$binary" "$INSTALL_DIR/$binary"
            log_success "Installed $binary"
            ((bin_count++))
        fi
    done

    if [ $bin_count -eq 0 ]; then
        log_error "No binaries found in archive"
        return 1
    fi
}

# Create go53 system user
create_system_user() {
    if id "$USER" &>/dev/null; then
        log_warn "User $USER already exists"
        return 0
    fi

    log_info "Creating system user $USER..."
    sudo useradd -r -s /bin/false -d "$DATA_DIR" -m "$USER" || {
        log_error "Failed to create user $USER"
        return 1
    }
    log_success "Created user $USER"
}

# Create directories
create_directories() {
    log_info "Creating configuration and data directories..."

    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$DATA_DIR"

    sudo chown "$USER:$GROUP" "$CONFIG_DIR"
    sudo chown "$USER:$GROUP" "$DATA_DIR"

    sudo chmod 755 "$CONFIG_DIR"
    sudo chmod 755 "$DATA_DIR"

    log_success "Directories created"
}

# Install systemd service file
install_systemd_service() {
    local service_file="/etc/systemd/system/go53.service"

    log_info "Installing systemd service..."

    sudo tee "$service_file" > /dev/null << 'EOF'
[Unit]
Description=go53 DNS Server
Documentation=https://github.com/TenforwardAB/go53
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=go53
Group=go53
WorkingDirectory=/var/lib/go53

# Main process
ExecStart=/usr/local/bin/go53

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/go53

# Process management
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=go53

[Install]
WantedBy=multi-user.target
EOF

    sudo chmod 644 "$service_file"
    log_success "Systemd service installed at $service_file"
}

# Enable and optionally start the service
setup_service() {
    log_info "Setting up systemd service..."

    sudo systemctl daemon-reload
    sudo systemctl enable go53.service
    log_success "Service enabled"

    log_info ""
    log_info "Service is ready to start. You can now:"
    echo -e "  ${YELLOW}sudo systemctl start go53${NC}       # Start the service"
    echo -e "  ${YELLOW}sudo systemctl status go53${NC}      # Check status"
    echo -e "  ${YELLOW}sudo systemctl stop go53${NC}        # Stop the service"
    echo -e "  ${YELLOW}journalctl -u go53 -f${NC}          # View logs"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    local missing=0

    if ! command -v go53 &> /dev/null; then
        log_error "go53 binary not found in PATH"
        ((missing++))
    else
        log_success "go53 is installed: $(go53 --version 2>/dev/null || echo 'version unknown')"
    fi

    if ! command -v go53ctl &> /dev/null; then
        log_error "go53ctl binary not found in PATH"
        ((missing++))
    else
        log_success "go53ctl is installed"
    fi

    if [ $missing -gt 0 ]; then
        log_error "Installation verification failed"
        return 1
    fi
}

# Main installation flow
main() {
    log_info "go53 Installation Script"
    log_info "GitHub Repository: https://github.com/${GITHUB_REPO}"
    log_info ""

    # Check if running with sudo
    if [ "$EUID" -ne 0 ] && ! command -v sudo &> /dev/null; then
        log_error "This script requires sudo or root privileges"
        exit 1
    fi

    # Detect platform
    log_info "Detecting platform..."
    local platform
    if ! platform=$(detect_platform); then
        exit 1
    fi
    log_success "Detected platform: $platform"

    # Determine version (fetch latest if not specified)
    if [ -z "$VERSION" ]; then
        if ! VERSION=$(get_latest_version); then
            exit 1
        fi
        log_success "Latest version: $VERSION"
    else
        log_info "Installing version: $VERSION"
    fi

    # Install binaries
    if ! install_binaries "$platform" "$VERSION"; then
        exit 1
    fi

    # Setup for Linux only
    if [[ "$platform" == linux* ]]; then
        log_info "Detected Linux, setting up systemd service..."

        if ! create_system_user; then
            exit 1
        fi

        if ! create_directories; then
            exit 1
        fi

        if ! install_systemd_service; then
            exit 1
        fi

        if ! setup_service; then
            exit 1
        fi
    else
        log_warn "macOS detected. Systemd service installation skipped."
        log_info "You can start go53 manually with: go53"
    fi

    # Verify installation
    if ! verify_installation; then
        exit 1
    fi

    log_info ""
    log_success "Installation completed successfully!"
    log_info "Version: $VERSION"
    log_info "Binaries installed to: $INSTALL_DIR"
    log_info ""

    if [[ "$platform" == linux* ]]; then
        log_info "Next steps:"
        echo -e "  1. Review configuration at: ${YELLOW}$CONFIG_DIR${NC}"
        echo -e "  2. Start the service: ${YELLOW}sudo systemctl start go53${NC}"
        echo -e "  3. Check status: ${YELLOW}sudo systemctl status go53${NC}"
        echo -e "  4. View logs: ${YELLOW}journalctl -u go53 -f${NC}"
    fi
}

main "$@"
