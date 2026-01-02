# GentlyOS

Content-addressable AI operating system. No files. No folders. Just hashes.

```
┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
│ a7f3 │  │ b8e4 │  │ c9f5 │  │ d0a6 │
│ wasm │  │tensor│  │manif │  │ svg  │
└──┬───┘  └──────┘  └──┬───┘  └──────┘
   │                   │
   └───────●───────────┘  (manifest refs)
```

## Core Concepts

**Everything is a Blob**
- `hash`: SHA256 of content (32 bytes)
- `kind`: discriminator (Wasm, Tensor, Manifest, SVG, etc.)
- `data`: raw bytes

**Manifests Link Blobs**
- No hierarchy, just a graph of references
- Tags replace names: `TAG_CODE`, `TAG_WEIGHTS`, `TAG_NEXT`

**SVG = Visual Container**
- Architecture visualization
- Holds WASM-compiled models
- Chains models: `A → B → C`

## Architecture

```
gently-core     ─► Blob store, XOR crypto, Dance protocol
gently-spl      ─► Tokens (GNTLY/GOS), NFTs, permissions
gently-brain    ─► LLM inference, Claude API, model chains
gently-ipfs     ─► Content sync, pinning
gently-btc      ─► Genesis anchoring
gently-cli      ─► Command interface
```

## Quick Start

```bash
# Build
cargo build --release

# Initialize genesis
./target/release/gently init

# Store a blob
./target/release/gently blob store "hello world"

# Run brain
./target/release/gently brain chat
```

## Docker

```bash
# Build and run
docker-compose up -d

# Check status
docker-compose logs gently
```

## Security Model

**XOR Split-Knowledge**
```
LOCK (device) ⊕ KEY (public) = SECRET
```
Neither half alone reveals anything. Dance protocol reconstructs during verification.

**Stake-Based Permissions**
- 51% GNTLY stake = root control
- Permissions cascade through tree
- Dance required for sensitive operations

## Tokens

| Token | Purpose |
|-------|---------|
| GNTLY | Governance, staking, permissions |
| GOS   | Gas for operations |
| GENOS | Rare genesis shares |

## Model Chains

```
embed.svg ──► classify.svg ──► output.svg
    │              │               │
    └─WASM─►       └─WASM─►        └─WASM─►
```

Each model: SVG visual + WASM code + schema + weights (optional)

## Development

```bash
# Test
cargo test --all

# Format
cargo fmt --all

# Lint
cargo clippy --all
```

## License

MIT
