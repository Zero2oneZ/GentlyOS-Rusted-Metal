#!/bin/bash
# GentlyOS DEB Package Builder
# Creates Ubuntu/Debian installable package

set -e

VERSION="${GENTLY_VERSION:-1.1.1}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/deb"
DIST_DIR="${PROJECT_ROOT}/dist"
PKG_NAME="gentlyos"
PKG_DIR="${BUILD_DIR}/${PKG_NAME}_${VERSION}_amd64"

echo "Building GentlyOS DEB package v${VERSION}..."

# Cleanup and setup
rm -rf "${BUILD_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/gentlyos"
mkdir -p "${PKG_DIR}/etc/gentlyos"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/usr/share/doc/gentlyos"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${DIST_DIR}"

# Copy binary
echo "[1/5] Copying binary..."
cp "${PROJECT_ROOT}/target/release/gently" "${PKG_DIR}/usr/local/bin/"
chmod 755 "${PKG_DIR}/usr/local/bin/gently"

# Create control file
echo "[2/5] Creating package metadata..."
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: security
Priority: optional
Architecture: amd64
Depends: ca-certificates, curl, jq, git, libssl3
Recommends: libpcap0.8
Suggests: docker.io
Maintainer: GentlyOS Project <contact@gentlyos.com>
Homepage: https://gentlyos.com
Description: Content-Addressable Security Operating System
 GentlyOS is a security-first operating system featuring:
  - BTC-anchored audit chain for immutable logging
  - 16+ security daemons running 24/7
  - Assume-hostile trust model
  - Local-first AI (Llama 1B + ONNX embedder)
  - Token distilling and credential protection
  - AI-irresistible honeypots
  - Content-addressable storage with SHA256 hashing
EOF

# Post-install script
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create gently user if not exists
if ! id -u gently &>/dev/null; then
    useradd -r -s /bin/false -d /var/lib/gentlyos gently
fi

# Create data directories
mkdir -p /var/lib/gentlyos/{blobs,genesis,knowledge,ipfs}
mkdir -p /var/log/gentlyos
chown -R gently:gently /var/lib/gentlyos
chown -R gently:gently /var/log/gentlyos

# Enable and start service
systemctl daemon-reload
systemctl enable gentlyos 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           GentlyOS installed successfully!                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║   Start the service:  sudo systemctl start gentlyos         ║"
echo "║   Check status:       sudo systemctl status gentlyos        ║"
echo "║   View logs:          journalctl -u gentlyos -f             ║"
echo "║                                                              ║"
echo "║   Or run directly:    gently                                 ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# Pre-remove script
cat > "${PKG_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Stop service if running
systemctl stop gentlyos 2>/dev/null || true
systemctl disable gentlyos 2>/dev/null || true

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# Systemd service file
echo "[3/5] Creating systemd service..."
cat > "${PKG_DIR}/lib/systemd/system/gentlyos.service" << EOF
[Unit]
Description=GentlyOS Security Service
Documentation=https://gentlyos.com/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gently
Group=gently
ExecStart=/usr/local/bin/gently daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/gentlyos /var/log/gentlyos

# Resource limits
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

# Default configuration
echo "[4/5] Creating default configuration..."
cat > "${PKG_DIR}/etc/gentlyos/config.toml" << EOF
# GentlyOS Configuration
# Version: ${VERSION}

[general]
data_dir = "/var/lib/gentlyos"
log_dir = "/var/log/gentlyos"
log_level = "info"

[security]
# Defense mode: normal, elevated, high, lockdown
defense_mode = "normal"
# Enable all security features
token_distilling = true
rate_limiting = true
threat_detection = true
trust_system = true
honeypots = true

[audit]
# BTC anchoring interval (seconds)
anchor_interval = 600
# Enable hash chain validation
chain_validation = true
# Audit log path
log_path = "/var/log/gentlyos/audit.log"

[providers]
# Local-first: prefer local AI
prefer_local = true
# Fallback to external APIs
allow_external = true

[limits]
# Global rate limit (requests/minute)
global_rpm = 60
# Per-session limit
session_rpm = 30
# Cost limits (USD)
daily_cost_limit = 10.0
monthly_cost_limit = 100.0
EOF

# Documentation
cat > "${PKG_DIR}/usr/share/doc/gentlyos/README" << EOF
GentlyOS v${VERSION}
====================

Content-Addressable Security Operating System

Quick Start:
  gently              - Start interactive mode
  gently daemon       - Run as background service
  gently status       - Check system status
  gently --help       - Show all commands

Configuration:
  /etc/gentlyos/config.toml

Data directories:
  /var/lib/gentlyos/blobs     - Content-addressable storage
  /var/lib/gentlyos/genesis   - Genesis chain data
  /var/lib/gentlyos/knowledge - Knowledge base
  /var/log/gentlyos           - Logs and audit trail

Documentation:
  https://gentlyos.com/docs

Support:
  https://github.com/gentlyos/gentlyos/issues

EOF

# Desktop entry (optional GUI launcher)
cat > "${PKG_DIR}/usr/share/applications/gentlyos.desktop" << EOF
[Desktop Entry]
Name=GentlyOS
Comment=Content-Addressable Security OS
Exec=x-terminal-emulator -e gently
Icon=security-high
Terminal=true
Type=Application
Categories=Security;System;
Keywords=security;ai;audit;
EOF

# Build package
echo "[5/5] Building DEB package..."
dpkg-deb --build --root-owner-group "${PKG_DIR}"
mv "${BUILD_DIR}/${PKG_NAME}_${VERSION}_amd64.deb" "${DIST_DIR}/"

# Generate checksums
cd "${DIST_DIR}"
sha256sum "${PKG_NAME}_${VERSION}_amd64.deb" > "${PKG_NAME}_${VERSION}_amd64.deb.sha256"

# Cleanup
rm -rf "${BUILD_DIR}"

echo ""
echo "DEB package built successfully!"
echo "  File: ${DIST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb"
echo "  Size: $(du -h "${DIST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb" | cut -f1)"
echo ""
echo "To install:"
echo "  sudo dpkg -i ${DIST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb"
echo "  sudo apt-get install -f  # Install dependencies if needed"
echo ""
echo "Or with apt:"
echo "  sudo apt install ./${DIST_DIR}/${PKG_NAME}_${VERSION}_amd64.deb"
