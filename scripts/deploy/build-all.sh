#!/bin/bash
# GentlyOS v1.1.1 - Master Build Script
# Builds all deployment targets

set -e

VERSION="1.1.1"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
DIST_DIR="${PROJECT_ROOT}/dist"

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
echo "║           GentlyOS v${VERSION} - Deployment Builder              ║"
echo "║                                                              ║"
echo "║   Targets: Docker | ISO | VirtualBox | Termux | DEB/RPM     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Setup directories
mkdir -p "${BUILD_DIR}" "${DIST_DIR}"

# Parse arguments
BUILD_DOCKER=false
BUILD_ISO=false
BUILD_VBOX=false
BUILD_TERMUX=false
BUILD_DEB=false
BUILD_ALL=false

if [ $# -eq 0 ]; then
    BUILD_ALL=true
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker) BUILD_DOCKER=true; shift ;;
        --iso) BUILD_ISO=true; shift ;;
        --vbox) BUILD_VBOX=true; shift ;;
        --termux) BUILD_TERMUX=true; shift ;;
        --deb) BUILD_DEB=true; shift ;;
        --all) BUILD_ALL=true; shift ;;
        *) error "Unknown option: $1" ;;
    esac
done

if $BUILD_ALL; then
    BUILD_DOCKER=true
    BUILD_ISO=true
    BUILD_VBOX=true
    BUILD_DEB=true
    # Termux requires Android NDK, skip in --all
fi

# Step 1: Build Rust binary
log "Building GentlyOS binary..."
cd "${PROJECT_ROOT}"
cargo build --release -p gently-cli
success "Binary built: target/release/gently"

# Step 2: Docker
if $BUILD_DOCKER; then
    log "Building Docker images..."
    "${PROJECT_ROOT}/scripts/deploy/build-docker.sh"
    success "Docker images built"
fi

# Step 3: ISO
if $BUILD_ISO; then
    log "Building bootable ISO..."
    "${PROJECT_ROOT}/scripts/deploy/build-iso.sh"
    success "ISO built: dist/gentlyos-${VERSION}.iso"
fi

# Step 4: VirtualBox
if $BUILD_VBOX; then
    log "Building VirtualBox OVA..."
    "${PROJECT_ROOT}/scripts/deploy/build-virtualbox.sh"
    success "VirtualBox OVA built: dist/gentlyos-${VERSION}.ova"
fi

# Step 5: DEB package
if $BUILD_DEB; then
    log "Building DEB package..."
    "${PROJECT_ROOT}/scripts/deploy/build-deb.sh"
    success "DEB package built: dist/gentlyos_${VERSION}_amd64.deb"
fi

# Step 6: Termux
if $BUILD_TERMUX; then
    log "Building Termux package..."
    "${PROJECT_ROOT}/scripts/deploy/build-termux.sh"
    success "Termux package built"
fi

# Summary
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Build Complete                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
ls -la "${DIST_DIR}/" 2>/dev/null | while read line; do
    echo "║  $line"
done
echo "╚══════════════════════════════════════════════════════════════╝"
