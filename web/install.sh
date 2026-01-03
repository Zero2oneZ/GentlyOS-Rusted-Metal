#!/bin/bash
# GentlyOS Universal Installer
# curl -fsSL https://gentlyos.com/install.sh | sudo bash

set -e

VERSION="1.1.1"
GITHUB_REPO="gentlyos/gentlyos"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[GENTLY]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Banner
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║    ██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗   ██╗         ║"
echo "║   ██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║  ╚██╗ ██╔╝         ║"
echo "║   ██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║   ╚████╔╝          ║"
echo "║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║    ╚██╔╝           ║"
echo "║   ╚██████╔╝███████╗██║ ╚████║   ██║   ███████╗██║            ║"
echo "║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝            ║"
echo "║                                                              ║"
echo "║           Universal Installer v${VERSION}                       ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS and architecture
detect_os() {
    OS="unknown"
    ARCH="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ "$(uname)" = "Darwin" ]; then
        OS="macos"
    elif [ "$(uname -o 2>/dev/null)" = "Android" ]; then
        OS="android"
    fi

    case $(uname -m) in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *)       ARCH=$(uname -m) ;;
    esac

    log "Detected: $OS ($ARCH)"
}

# Check root
check_root() {
    if [ "$EUID" -ne 0 ] && [ "$OS" != "android" ]; then
        error "Please run as root: sudo bash install.sh"
    fi
}

# Install dependencies
install_deps() {
    log "Installing dependencies..."

    case $OS in
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq
            apt-get install -y -qq curl ca-certificates jq git
            ;;
        fedora|rhel|centos)
            dnf install -y curl ca-certificates jq git
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm curl ca-certificates jq git
            ;;
        alpine)
            apk add --no-cache curl ca-certificates jq git
            ;;
        macos)
            if ! command -v brew &>/dev/null; then
                warn "Homebrew not found. Install from https://brew.sh"
            else
                brew install curl jq git
            fi
            ;;
        android)
            pkg install -y curl jq git
            ;;
        *)
            warn "Unknown OS. Attempting to continue..."
            ;;
    esac
}

# Download and install binary
install_binary() {
    log "Downloading GentlyOS v${VERSION}..."

    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/gently-${ARCH}"

    # Try GitHub release first
    if curl -fsSL -o /tmp/gently "${DOWNLOAD_URL}" 2>/dev/null; then
        log "Downloaded from GitHub releases"
    else
        # Fallback to gentlyos.com
        DOWNLOAD_URL="https://gentlyos.com/releases/gently-${VERSION}-${ARCH}"
        curl -fsSL -o /tmp/gently "${DOWNLOAD_URL}" || error "Download failed"
    fi

    # Verify download
    if [ ! -f /tmp/gently ]; then
        error "Download failed"
    fi

    # Install binary
    chmod +x /tmp/gently

    if [ "$OS" = "android" ]; then
        mv /tmp/gently "$PREFIX/bin/gently"
    else
        mv /tmp/gently "${INSTALL_DIR}/gently"
    fi

    success "Binary installed to ${INSTALL_DIR}/gently"
}

# Setup configuration
setup_config() {
    log "Setting up configuration..."

    if [ "$OS" = "android" ]; then
        CONFIG_DIR="$HOME/.gentlyos"
    else
        CONFIG_DIR="/etc/gentlyos"
        DATA_DIR="/var/lib/gentlyos"
        LOG_DIR="/var/log/gentlyos"

        mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

        # Create default config if not exists
        if [ ! -f "$CONFIG_DIR/config.toml" ]; then
            cat > "$CONFIG_DIR/config.toml" << EOF
# GentlyOS Configuration
# Version: ${VERSION}

[general]
data_dir = "${DATA_DIR}"
log_dir = "${LOG_DIR}"
log_level = "info"

[security]
defense_mode = "normal"
token_distilling = true
rate_limiting = true
threat_detection = true

[audit]
anchor_interval = 600
chain_validation = true
EOF
        fi
    fi
}

# Setup systemd service (Linux only)
setup_service() {
    if [ "$OS" = "android" ] || [ "$OS" = "macos" ]; then
        return
    fi

    if command -v systemctl &>/dev/null; then
        log "Setting up systemd service..."

        cat > /lib/systemd/system/gentlyos.service << EOF
[Unit]
Description=GentlyOS Security Service
After=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/gently daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable gentlyos

        success "Systemd service created (not started)"
    fi
}

# Verify installation
verify_install() {
    log "Verifying installation..."

    if command -v gently &>/dev/null; then
        INSTALLED_VERSION=$(gently --version 2>/dev/null | head -1 || echo "unknown")
        success "GentlyOS installed: ${INSTALLED_VERSION}"
    else
        error "Installation verification failed"
    fi
}

# Print completion message
print_completion() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Installation Complete!                             ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo "║   Quick Start:                                               ║"
    echo "║     gently              - Start interactive mode             ║"
    echo "║     gently status       - Check system status                ║"
    echo "║     gently --help       - Show all commands                  ║"
    echo "║                                                              ║"

    if [ "$OS" != "android" ] && [ "$OS" != "macos" ]; then
        echo "║   Service Management:                                        ║"
        echo "║     sudo systemctl start gentlyos                            ║"
        echo "║     sudo systemctl status gentlyos                           ║"
        echo "║                                                              ║"
    fi

    echo "║   Documentation: https://gentlyos.com/docs                   ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Main
main() {
    detect_os
    check_root
    install_deps
    install_binary
    setup_config
    setup_service
    verify_install
    print_completion
}

main "$@"
