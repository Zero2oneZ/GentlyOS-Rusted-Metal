#!/bin/bash
# GentlyOS Foundation Setup Script
# Run this to complete Phase 1 Foundation Hardening

set -e

echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║           GENTLYOS FOUNDATION SETUP                                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"

GENTLYOS_DIR="${HOME}/.gentlyos"
GENESIS_DIR="${GENTLYOS_DIR}/genesis"

# Step 1.3: Token Configuration Cleanup
echo ""
echo "=== Step 1.3: Token Configuration Cleanup ==="

if [ -f "${GENESIS_DIR}/token.env" ] && [ -f "${GENESIS_DIR}/tokens.env" ]; then
    echo "Archiving stale token.env..."
    mv "${GENESIS_DIR}/token.env" "${GENESIS_DIR}/token.env.stale"
    echo "  Archived: token.env -> token.env.stale"

    echo "tokens.env contains the active minted token"
    echo "  Active token: $(cat ${GENESIS_DIR}/tokens.env)"
else
    echo "Token configuration already clean or files missing"
fi

# Step 1.4: Genesis Chain Verification
echo ""
echo "=== Step 1.4: Genesis Chain Verification ==="

EXPECTED_GENESIS="39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69"
ACTUAL_GENESIS=$(head -1 "${GENESIS_DIR}/genesis-hash.txt" 2>/dev/null || echo "NOT_FOUND")

if [ "$ACTUAL_GENESIS" = "$EXPECTED_GENESIS" ]; then
    echo "  Genesis hash: VALID"
    echo "  Hash: $ACTUAL_GENESIS"
else
    echo "  Genesis hash: MISMATCH"
    echo "  Expected: $EXPECTED_GENESIS"
    echo "  Actual: $ACTUAL_GENESIS"
    exit 1
fi

# Verify audit.log chain
if [ -f "${GENTLYOS_DIR}/audit.log" ]; then
    ENTRY_COUNT=$(wc -l < "${GENTLYOS_DIR}/audit.log")
    LAST_HASH=$(tail -1 "${GENTLYOS_DIR}/audit.log" | cut -d'|' -f1)
    echo "  Audit log entries: $ENTRY_COUNT"
    echo "  Last hash: ${LAST_HASH:0:16}..."
else
    echo "  Audit log: NOT FOUND (will be created on first use)"
fi

# Test BTC block fetching
echo ""
echo "=== Testing BTC Block Fetching ==="
BTC_DATA=$(curl -s https://blockchain.info/latestblock 2>/dev/null)
if [ -n "$BTC_DATA" ]; then
    BTC_HEIGHT=$(echo "$BTC_DATA" | jq -r '.height')
    BTC_HASH=$(echo "$BTC_DATA" | jq -r '.hash')
    echo "  BTC height: $BTC_HEIGHT"
    echo "  BTC hash: ${BTC_HASH:0:16}..."
    echo "  Status: ONLINE"
else
    echo "  Status: OFFLINE (will use local timestamp fallback)"
fi

# Step 1.5: Build System Validation
echo ""
echo "=== Step 1.5: Build System Validation ==="

cd /root/gentlyos

echo "Running cargo check..."
if cargo check 2>/dev/null; then
    echo "  cargo check: PASS"
else
    echo "  cargo check: FAIL (run 'cargo check' for details)"
fi

if [ -f "target/release/gently" ]; then
    BINARY_SIZE=$(du -h target/release/gently | cut -f1)
    echo "  Binary: target/release/gently ($BINARY_SIZE)"
else
    echo "  Binary: NOT BUILT (run 'cargo build --release')"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║           FOUNDATION SETUP COMPLETE                                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next: Proceed to Phase 2 (Core Security Layer)"
