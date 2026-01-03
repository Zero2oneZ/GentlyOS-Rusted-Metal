#!/bin/bash
# GentlyOS ISO Builder
# Creates bootable live USB image (Kali-style)

set -e

VERSION="${GENTLY_VERSION:-1.1.1}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/iso"
DIST_DIR="${PROJECT_ROOT}/dist"
ISO_NAME="gentlyos-${VERSION}-amd64.iso"

# Cleanup and setup
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"/{staging,isolinux,live,boot/grub}
mkdir -p "${DIST_DIR}"

echo "Building GentlyOS Live ISO v${VERSION}..."

# Check dependencies
for cmd in debootstrap mksquashfs xorriso grub-mkrescue; do
    if ! command -v $cmd &> /dev/null; then
        echo "Installing $cmd..."
        apt-get update && apt-get install -y $cmd live-build squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin
    fi
done

# Step 1: Create minimal Debian base
echo "[1/6] Building base system..."
debootstrap --arch=amd64 --variant=minbase bookworm "${BUILD_DIR}/staging" http://deb.debian.org/debian

# Step 2: Configure chroot
echo "[2/6] Configuring system..."
cat > "${BUILD_DIR}/staging/setup.sh" << 'CHROOT_SCRIPT'
#!/bin/bash
set -e

# Set hostname
echo "gentlyos" > /etc/hostname

# Configure apt
cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
EOF

apt-get update

# Install essential packages
apt-get install -y --no-install-recommends \
    linux-image-amd64 \
    live-boot \
    systemd-sysv \
    network-manager \
    openssh-client \
    curl \
    ca-certificates \
    git \
    jq \
    vim-tiny \
    sudo \
    locales

# Configure locale
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen

# Create gently user
useradd -m -s /bin/bash -G sudo gently
echo "gently:gently" | chpasswd
echo "gently ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Configure auto-login
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin gently --noclear %I \$TERM
EOF

# Welcome message
cat > /etc/motd << 'EOF'

 ╔══════════════════════════════════════════════════════════════════╗
 ║                                                                  ║
 ║    ██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗   ██╗             ║
 ║   ██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║  ╚██╗ ██╔╝             ║
 ║   ██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║   ╚████╔╝              ║
 ║   ██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║    ╚██╔╝               ║
 ║   ╚██████╔╝███████╗██║ ╚████║   ██║   ███████╗██║                ║
 ║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝                ║
 ║                                                                  ║
 ║   Content-Addressable Security OS                    v1.1.1      ║
 ║                                                                  ║
 ║   Run 'gently' to start                                          ║
 ║   Run 'gently --help' for commands                               ║
 ║                                                                  ║
 ╚══════════════════════════════════════════════════════════════════╝

EOF

# Configure bashrc for gently user
cat >> /home/gently/.bashrc << 'EOF'

# GentlyOS Environment
export GENTLY_DATA_DIR=$HOME/.gentlyos
export PATH=$PATH:/usr/local/bin

# Start message
if [ -z "$GENTLY_STARTED" ]; then
    export GENTLY_STARTED=1
    echo ""
    echo "Type 'gently' to begin..."
    echo ""
fi
EOF

# Cleanup
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -rf /tmp/*
CHROOT_SCRIPT

chmod +x "${BUILD_DIR}/staging/setup.sh"
chroot "${BUILD_DIR}/staging" /setup.sh
rm "${BUILD_DIR}/staging/setup.sh"

# Step 3: Copy GentlyOS binary
echo "[3/6] Installing GentlyOS..."
cp "${PROJECT_ROOT}/target/release/gently" "${BUILD_DIR}/staging/usr/local/bin/"
chmod +x "${BUILD_DIR}/staging/usr/local/bin/gently"

# Copy genesis data if exists
if [ -d "${HOME}/.gentlyos/genesis" ]; then
    mkdir -p "${BUILD_DIR}/staging/etc/gentlyos"
    cp -r "${HOME}/.gentlyos/genesis" "${BUILD_DIR}/staging/etc/gentlyos/"
fi

# Step 4: Create squashfs
echo "[4/6] Creating squashfs filesystem..."
mksquashfs "${BUILD_DIR}/staging" "${BUILD_DIR}/live/filesystem.squashfs" \
    -comp xz -b 1M -Xdict-size 100%

# Copy kernel and initrd
cp "${BUILD_DIR}/staging/boot/vmlinuz-"* "${BUILD_DIR}/live/vmlinuz"
cp "${BUILD_DIR}/staging/boot/initrd.img-"* "${BUILD_DIR}/live/initrd"

# Step 5: Configure bootloader
echo "[5/6] Configuring bootloader..."

# GRUB config
cat > "${BUILD_DIR}/boot/grub/grub.cfg" << 'EOF'
set timeout=5
set default=0

menuentry "GentlyOS Live" {
    linux /live/vmlinuz boot=live quiet splash
    initrd /live/initrd
}

menuentry "GentlyOS Live (Safe Mode)" {
    linux /live/vmlinuz boot=live nomodeset
    initrd /live/initrd
}

menuentry "GentlyOS Live (To RAM)" {
    linux /live/vmlinuz boot=live toram quiet
    initrd /live/initrd
}

menuentry "Install GentlyOS" {
    linux /live/vmlinuz boot=live installer quiet
    initrd /live/initrd
}
EOF

# Step 6: Create ISO
echo "[6/6] Building ISO..."
grub-mkrescue -o "${DIST_DIR}/${ISO_NAME}" "${BUILD_DIR}" \
    --product-name="GentlyOS" \
    --product-version="${VERSION}"

# Calculate checksums
cd "${DIST_DIR}"
sha256sum "${ISO_NAME}" > "${ISO_NAME}.sha256"
md5sum "${ISO_NAME}" > "${ISO_NAME}.md5"

# Cleanup
rm -rf "${BUILD_DIR}"

echo ""
echo "ISO built successfully!"
echo "  File: ${DIST_DIR}/${ISO_NAME}"
echo "  Size: $(du -h "${DIST_DIR}/${ISO_NAME}" | cut -f1)"
echo ""
echo "To write to USB:"
echo "  sudo dd if=${DIST_DIR}/${ISO_NAME} of=/dev/sdX bs=4M status=progress"
