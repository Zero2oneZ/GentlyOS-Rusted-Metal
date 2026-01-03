#!/bin/bash
# GentlyOS VirtualBox OVA Builder
# Creates ready-to-import VirtualBox appliance

set -e

VERSION="${GENTLY_VERSION:-1.1.1}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/vbox"
DIST_DIR="${PROJECT_ROOT}/dist"
VM_NAME="GentlyOS-${VERSION}"
OVA_NAME="gentlyos-${VERSION}.ova"

# VM specs
VM_RAM=2048
VM_CPUS=2
VM_DISK=20480  # 20GB

echo "Building GentlyOS VirtualBox OVA v${VERSION}..."

# Check dependencies
if ! command -v VBoxManage &> /dev/null; then
    echo "VirtualBox not found. Please install VirtualBox."
    echo "  Ubuntu: sudo apt install virtualbox"
    echo "  macOS:  brew install virtualbox"
    exit 1
fi

# Cleanup any existing VM
VBoxManage unregistervm "${VM_NAME}" --delete 2>/dev/null || true

# Setup directories
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${DIST_DIR}"

# Check for ISO
ISO_PATH="${DIST_DIR}/gentlyos-${VERSION}-amd64.iso"
if [ ! -f "${ISO_PATH}" ]; then
    echo "ISO not found at ${ISO_PATH}"
    echo "Building ISO first..."
    "${PROJECT_ROOT}/scripts/deploy/build-iso.sh"
fi

echo "[1/5] Creating virtual machine..."
VBoxManage createvm \
    --name "${VM_NAME}" \
    --ostype "Debian_64" \
    --register \
    --basefolder "${BUILD_DIR}"

echo "[2/5] Configuring hardware..."
VBoxManage modifyvm "${VM_NAME}" \
    --memory ${VM_RAM} \
    --cpus ${VM_CPUS} \
    --vram 32 \
    --acpi on \
    --ioapic on \
    --rtcuseutc on \
    --boot1 disk \
    --boot2 dvd \
    --boot3 none \
    --boot4 none \
    --nic1 nat \
    --natpf1 "ssh,tcp,,2222,,22" \
    --natpf1 "mcp,tcp,,3000,,3000" \
    --natpf1 "health,tcp,,8080,,8080" \
    --audio-driver none \
    --usb on \
    --usbehci off \
    --clipboard bidirectional \
    --draganddrop bidirectional \
    --description "GentlyOS v${VERSION} - Content-Addressable Security OS"

echo "[3/5] Creating disk..."
VBoxManage createhd \
    --filename "${BUILD_DIR}/${VM_NAME}/${VM_NAME}.vdi" \
    --size ${VM_DISK} \
    --format VDI \
    --variant Standard

# Create SATA controller
VBoxManage storagectl "${VM_NAME}" \
    --name "SATA" \
    --add sata \
    --controller IntelAhci \
    --portcount 2

# Attach disk
VBoxManage storageattach "${VM_NAME}" \
    --storagectl "SATA" \
    --port 0 \
    --device 0 \
    --type hdd \
    --medium "${BUILD_DIR}/${VM_NAME}/${VM_NAME}.vdi"

# Attach ISO for installation
VBoxManage storageattach "${VM_NAME}" \
    --storagectl "SATA" \
    --port 1 \
    --device 0 \
    --type dvddrive \
    --medium "${ISO_PATH}"

echo "[4/5] Installing OS (headless)..."
echo "This will take several minutes..."

# Start VM headless for unattended install
VBoxManage startvm "${VM_NAME}" --type headless

# Wait for installation (monitor for shutdown)
echo "Waiting for installation to complete..."
while VBoxManage showvminfo "${VM_NAME}" --machinereadable | grep -q "VMState=\"running\""; do
    sleep 10
    echo -n "."
done
echo ""

# Detach ISO
VBoxManage storageattach "${VM_NAME}" \
    --storagectl "SATA" \
    --port 1 \
    --device 0 \
    --type dvddrive \
    --medium emptydrive

echo "[5/5] Exporting OVA..."
VBoxManage export "${VM_NAME}" \
    --output "${DIST_DIR}/${OVA_NAME}" \
    --ovf20 \
    --manifest \
    --options manifest,nomacs \
    --vsys 0 \
    --product "GentlyOS" \
    --producturl "https://gentlyos.com" \
    --vendor "GentlyOS Project" \
    --vendorurl "https://gentlyos.com" \
    --version "${VERSION}" \
    --description "GentlyOS - Content-Addressable Security Operating System. Features: BTC-anchored audit chain, 16+ security daemons, assume-hostile trust model, local-first AI."

# Cleanup VM (keep OVA)
VBoxManage unregistervm "${VM_NAME}" --delete

# Generate checksums
cd "${DIST_DIR}"
sha256sum "${OVA_NAME}" > "${OVA_NAME}.sha256"

echo ""
echo "VirtualBox OVA built successfully!"
echo "  File: ${DIST_DIR}/${OVA_NAME}"
echo "  Size: $(du -h "${DIST_DIR}/${OVA_NAME}" | cut -f1)"
echo ""
echo "To import:"
echo "  VBoxManage import ${DIST_DIR}/${OVA_NAME}"
echo "  - or -"
echo "  File > Import Appliance in VirtualBox GUI"
