#!/bin/bash
# GentlyOS Termux Package Builder
# Creates package for Android via Termux

set -e

VERSION="${GENTLY_VERSION:-1.1.1}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/termux"
DIST_DIR="${PROJECT_ROOT}/dist"

echo "Building GentlyOS Termux package v${VERSION}..."

# Termux builds require cross-compilation to aarch64-linux-android
# This script sets up the toolchain and builds

# Check for Android NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "ANDROID_NDK_HOME not set. Checking common locations..."
    for ndk_path in \
        "$HOME/Android/Sdk/ndk/"* \
        "/opt/android-ndk-"* \
        "/usr/local/android-ndk-"*; do
        if [ -d "$ndk_path" ]; then
            export ANDROID_NDK_HOME="$ndk_path"
            break
        fi
    done
fi

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo ""
    echo "Android NDK not found. To build for Termux, you need:"
    echo ""
    echo "1. Install Android NDK:"
    echo "   - Download from: https://developer.android.com/ndk/downloads"
    echo "   - Or via Android Studio SDK Manager"
    echo ""
    echo "2. Set environment variable:"
    echo "   export ANDROID_NDK_HOME=/path/to/android-ndk-rXX"
    echo ""
    echo "3. Run this script again"
    echo ""
    echo "Alternatively, build on an Android device with Termux:"
    echo "   pkg install rust"
    echo "   cargo build --release -p gently-cli"
    echo ""
    exit 1
fi

echo "Using NDK: $ANDROID_NDK_HOME"

# Setup directories
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${DIST_DIR}"

# Configure Rust for cross-compilation
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="aarch64-linux-android"
API_LEVEL="24"  # Android 7.0+

export CC_aarch64_linux_android="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang"
export CXX_aarch64_linux_android="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang++"
export AR_aarch64_linux_android="${TOOLCHAIN}/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang"

# Add Rust target
rustup target add aarch64-linux-android 2>/dev/null || true

# Create cargo config for cross-compilation
mkdir -p "${PROJECT_ROOT}/.cargo"
cat > "${PROJECT_ROOT}/.cargo/config.toml" << EOF
[target.aarch64-linux-android]
linker = "${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang"

[target.armv7-linux-androideabi]
linker = "${TOOLCHAIN}/bin/armv7a-linux-androideabi${API_LEVEL}-clang"

[target.x86_64-linux-android]
linker = "${TOOLCHAIN}/bin/x86_64-linux-android${API_LEVEL}-clang"
EOF

echo "[1/4] Cross-compiling for Android (aarch64)..."
cd "${PROJECT_ROOT}"
cargo build --release --target aarch64-linux-android -p gently-cli

# Copy binary
cp "${PROJECT_ROOT}/target/aarch64-linux-android/release/gently" "${BUILD_DIR}/"

echo "[2/4] Creating Termux package structure..."

# Create Termux package (deb format)
PKG_DIR="${BUILD_DIR}/gentlyos_${VERSION}_aarch64"
mkdir -p "${PKG_DIR}/data/data/com.termux/files/usr/bin"
mkdir -p "${PKG_DIR}/data/data/com.termux/files/usr/share/gentlyos"
mkdir -p "${PKG_DIR}/DEBIAN"

cp "${BUILD_DIR}/gently" "${PKG_DIR}/data/data/com.termux/files/usr/bin/"
chmod 755 "${PKG_DIR}/data/data/com.termux/files/usr/bin/gently"

# Termux control file
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: gentlyos
Version: ${VERSION}
Architecture: aarch64
Maintainer: GentlyOS Project <contact@gentlyos.com>
Homepage: https://gentlyos.com
Depends: openssl, curl, git
Description: Content-Addressable Security OS for Android
 GentlyOS brings enterprise-grade security to your Android device.
 Features include BTC-anchored audit chains, local AI, and
 16+ security daemons for comprehensive protection.
EOF

# Post-install for Termux
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/data/data/com.termux/files/usr/bin/sh

# Create config directory
mkdir -p ~/.gentlyos

echo ""
echo "GentlyOS installed successfully!"
echo ""
echo "Run 'gently' to start"
echo "Run 'gently --help' for commands"
echo ""

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

echo "[3/4] Building Termux package..."
dpkg-deb --build --root-owner-group "${PKG_DIR}"
mv "${BUILD_DIR}/gentlyos_${VERSION}_aarch64.deb" "${DIST_DIR}/gentlyos_${VERSION}_termux_aarch64.deb"

# Create install script for Termux users
echo "[4/4] Creating install helper..."
cat > "${DIST_DIR}/install-termux.sh" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# GentlyOS Termux Installer
# Run this script in Termux to install GentlyOS

set -e

VERSION="1.1.1"
ARCH=$(uname -m)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           GentlyOS Termux Installer                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Update Termux
echo "[1/4] Updating Termux..."
pkg update -y
pkg upgrade -y

# Install dependencies
echo "[2/4] Installing dependencies..."
pkg install -y openssl curl git jq

# Download package
echo "[3/4] Downloading GentlyOS..."
PKG_URL="https://gentlyos.com/download/gentlyos_${VERSION}_termux_aarch64.deb"
curl -L -o "/tmp/gentlyos.deb" "${PKG_URL}"

# Install
echo "[4/4] Installing..."
dpkg -i "/tmp/gentlyos.deb"
rm "/tmp/gentlyos.deb"

echo ""
echo "Installation complete! Run 'gently' to start."
echo ""
EOF
chmod 755 "${DIST_DIR}/install-termux.sh"

# Generate checksums
cd "${DIST_DIR}"
sha256sum "gentlyos_${VERSION}_termux_aarch64.deb" > "gentlyos_${VERSION}_termux_aarch64.deb.sha256"

# Cleanup cargo config
rm -f "${PROJECT_ROOT}/.cargo/config.toml"

echo ""
echo "Termux package built successfully!"
echo "  File: ${DIST_DIR}/gentlyos_${VERSION}_termux_aarch64.deb"
echo "  Size: $(du -h "${DIST_DIR}/gentlyos_${VERSION}_termux_aarch64.deb" | cut -f1)"
echo ""
echo "Installation on Android:"
echo "  1. Install Termux from F-Droid (not Play Store)"
echo "  2. Run: curl -sL https://gentlyos.com/install-termux.sh | bash"
echo ""
echo "Or manually:"
echo "  1. Copy .deb to device"
echo "  2. In Termux: dpkg -i gentlyos_${VERSION}_termux_aarch64.deb"
