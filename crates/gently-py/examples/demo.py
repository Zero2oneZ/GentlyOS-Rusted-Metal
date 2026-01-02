#!/usr/bin/env python3
"""
GentlyOS Python Demo

Build and install first:
    cd crates/gently-py
    pip install maturin
    maturin develop

Then run this script:
    python examples/demo.py
"""

import gently
import os

def main():
    print("=" * 60)
    print("  GENTLYOS PYTHON BINDINGS DEMO")
    print("=" * 60)
    print()

    # 1. Generate a random secret
    print("1. Generating random 32-byte secret...")
    secret = os.urandom(32)
    print(f"   Secret: {secret.hex()[:32]}...")
    print()

    # 2. Split into Lock + Key
    print("2. Splitting secret into Lock + Key...")
    lock, key = gently.split_secret(secret)
    print(f"   Lock: {lock}")
    print(f"   Key:  {key}")
    print()

    # 3. Recombine to verify
    print("3. Combining Lock + Key to recover secret...")
    recovered = lock.combine(key)
    recovered_bytes = bytes(recovered.to_bytes())
    print(f"   Recovered: {recovered_bytes.hex()[:32]}...")
    print(f"   Match: {recovered_bytes == secret}")
    print()

    # 4. Generate visual pattern
    print("4. Encoding secret as visual/audio pattern...")
    pattern = gently.encode_pattern(secret)
    print(f"   Visual: {pattern.visual_name}")
    print(f"   Color:  {pattern.color_hex} (RGB: {pattern.color_rgb})")
    print(f"   Shape:  {pattern.shape}")
    print(f"   Motion: {pattern.motion}")
    print(f"   Freq:   {pattern.frequency_hz:.1f} Hz")
    print(f"   Chord:  {pattern.chord}")
    print(f"   Rhythm: {pattern.rhythm}")
    print()

    # 5. Render to SVG
    print("5. Rendering pattern to SVG...")
    svg = gently.render_svg(pattern, width=200, height=200)
    print(f"   SVG length: {len(svg)} bytes")
    print(f"   Preview: {svg[:80]}...")
    print()

    # 6. Generate decoys
    print("6. Generating 3 decoy patterns...")
    decoys = gently.generate_decoys(pattern, count=3)
    for i, decoy in enumerate(decoys):
        print(f"   Decoy {i+1}: {len(decoy)} bytes")
    print()

    # 7. Genesis key demo
    print("7. Genesis key derivation...")
    genesis = gently.GenesisKey.from_seed("my secret phrase", "my-salt")
    print(f"   Genesis: {genesis}")
    print(f"   Fingerprint: {bytes(genesis.fingerprint()).hex()}")

    child1 = genesis.derive(b"session-2024")
    child2 = genesis.derive(b"project-foo")
    print(f"   Session key:  {bytes(child1).hex()[:16]}...")
    print(f"   Project key:  {bytes(child2).hex()[:16]}...")
    print()

    # 8. XOR demo
    print("8. XOR bytes utility...")
    a = bytes([0xFF, 0x00, 0xAA, 0x55])
    b = bytes([0x0F, 0xF0, 0x55, 0xAA])
    result = gently.xor_bytes(a, b)
    print(f"   {a.hex()} XOR {b.hex()} = {bytes(result).hex()}")
    print()

    print("=" * 60)
    print("  XOR SPLIT-KNOWLEDGE SECURITY")
    print("=" * 60)
    print()
    print("  LOCK alone = random noise (reveals nothing)")
    print("  KEY alone  = random noise (reveals nothing)")
    print("  LOCK ⊕ KEY = FULL_SECRET (requires BOTH)")
    print()
    print("  The KEY can be public. The LOCK never leaves your device.")
    print("  Neither half alone can ever reveal the secret.")
    print()

if __name__ == "__main__":
    main()
