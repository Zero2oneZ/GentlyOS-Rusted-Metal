#!/bin/bash
# GentlyOS Universal Installer
# curl -fsSL https://gentlyos.com/install.sh | sudo bash

set -e

VERSION="1.0.0"
GITHUB_REPO="Zero2oneZ/GentlyOS-Rusted-Metal"
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

# Install Rust toolchain (for source builds)
install_rust() {
    if command -v rustc &>/dev/null; then
        log "Rust already installed: $(rustc --version)"
        return 0
    fi

    log "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    success "Rust installed: $(rustc --version)"
}

# Build from source (fallback)
build_from_source() {
    log "Building from source..."

    install_rust

    # Clone repository
    TEMP_DIR=$(mktemp -d)
    git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TEMP_DIR/gentlyos"
    cd "$TEMP_DIR/gentlyos"

    # Build release
    cargo build --release -p gently-cli

    # Install binary
    if [ "$OS" = "android" ]; then
        cp target/release/gently "$PREFIX/bin/gently"
    else
        cp target/release/gently "${INSTALL_DIR}/gently"
    fi

    # Cleanup
    cd -
    rm -rf "$TEMP_DIR"

    success "Built and installed from source"
}

# Setup user data directory
setup_user_data() {
    log "Setting up user data directory..."

    USER_DATA_DIR="$HOME/.gently"
    mkdir -p "$USER_DATA_DIR"/{alexandria,brain,feed,models,vault}

    # Create default user config
    if [ ! -f "$USER_DATA_DIR/config.toml" ]; then
        cat > "$USER_DATA_DIR/config.toml" << EOF
# GentlyOS User Configuration
# Version: ${VERSION}

[user]
# data_dir = "${USER_DATA_DIR}"

[embeddings]
# model = "BAAI/bge-small-en-v1.5"
# cache_dir = "${USER_DATA_DIR}/models"

[alexandria]
# graph_path = "${USER_DATA_DIR}/alexandria/graph.json"

[brain]
# knowledge_db = "${USER_DATA_DIR}/brain/knowledge.db"
EOF
    fi

    success "User data directory created at ${USER_DATA_DIR}"
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

# Run initial setup wizard
run_setup_wizard() {
    log "Running initial setup..."

    # Check if already initialized
    if [ -f "$HOME/.gently/vault/genesis.key" ]; then
        log "Already initialized. Skipping setup wizard."
        return 0
    fi

    # Run gently init if available
    if command -v gently &>/dev/null; then
        log "Running 'gently init' to generate genesis keys..."
        gently init --non-interactive 2>/dev/null || {
            warn "Interactive init required. Run 'gently init' manually."
        }
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
    # Parse arguments
    FROM_SOURCE=false
    SKIP_SETUP=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --source)
                FROM_SOURCE=true
                shift
                ;;
            --skip-setup)
                SKIP_SETUP=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    detect_os
    check_root
    install_deps

    if [ "$FROM_SOURCE" = true ]; then
        build_from_source
    else
        install_binary || {
            warn "Binary download failed. Building from source..."
            build_from_source
        }
    fi

    setup_config
    setup_user_data
    setup_service
    verify_install

    if [ "$SKIP_SETUP" = false ]; then
        run_setup_wizard
    fi

    print_completion
}

main "$@"
