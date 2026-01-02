# GentlyOS Architecture

## Philosophy

**GentlyOS is a runtime for living SVGs.**

The SVG IS the agent. Self-contained. Self-executing. Self-improving.

```
┌─────────────────────────────────────────┐
│  agent.svg (hash: 7f3a...)              │
├─────────────────────────────────────────┤
│  <svg>                                  │
│    <!-- VISUAL: What I am -->           │
│    <rect>, <path>, <text>...            │
│                                         │
│    <!-- BRAIN: What I do -->            │
│    <foreignObject>                      │
│      <wasm src="data:..." />            │
│    </foreignObject>                     │
│                                         │
│    <!-- MEMORY: What I learned -->      │
│    <metadata>                           │
│      lora_chain: 8b4c...                │
│      parent: 6a2f...                    │
│    </metadata>                          │
│  </svg>                                 │
└─────────────────────────────────────────┘

Open in browser → see what it is
Run in WASM → it thinks
Failure → pattern → LoRA → new SVG hash
Fork → your version → your hash
```

Content-addressable storage. Hash = identity. No filesystem hierarchy.

```
Traditional:  /home/user/models/llama/weights.bin
GentlyOS:     a7f3e2b1...  (hash of weights)
```

## The Primitive

```rust
struct Blob {
    hash: [u8; 32],  // SHA256 of data
    kind: Kind,      // discriminator
    data: Vec<u8>,   // raw bytes
}

enum Kind {
    Raw        = 0x00,  // unknown bytes
    Wasm       = 0x01,  // executable code
    Tensor     = 0x02,  // weights
    Manifest   = 0x03,  // links other hashes
    Delta      = 0x04,  // patch
    Schema     = 0x05,  // tensor shape
    Svg        = 0x06,  // visual container
    Checkpoint = 0x07,  // inference state
    Genesis    = 0x08,  // root key
    Lock       = 0x09,  // XOR half
    Key        = 0x0A,  // other half
    Vector     = 0x0B,  // embedding
    Text       = 0x0C,  // utf8
    Json       = 0x0D,  // json
    Audio      = 0x0E,  // samples
    Signed     = 0x0F,  // signature wrapper
}
```

## Storage

One flat pool of hashes. No directories.

```rust
struct BlobStore {
    blobs: HashMap<Hash, Blob>,
    index: Index,
}

struct Index {
    by_kind: BTreeMap<u8, BTreeSet<Hash>>,
    by_tag: BTreeMap<(Hash, Tag), BTreeSet<Hash>>,
    roots: BTreeSet<Hash>,
}
```

## Relationships

Manifests link blobs with tags:

```rust
struct Manifest {
    refs: Vec<Ref>,
}

struct Ref {
    tag: Tag,    // u16 relationship type
    hash: Hash,  // target blob
}

// Standard tags
TAG_ENTRY   = 0x0001
TAG_PARENT  = 0x0002
TAG_CHILD   = 0x0003
TAG_SCHEMA  = 0x0004
TAG_NEXT    = 0x0005
TAG_PREV    = 0x0006
TAG_WEIGHTS = 0x0007
TAG_CODE    = 0x0008
TAG_CONFIG  = 0x0009
```

## Lookup Without Names

```rust
// Find by kind
store.by_kind(Kind::Wasm)  // all WASM blobs

// Find by relationship
store.children(parent_hash, TAG_WEIGHTS)  // weights of a model

// Traverse graph
store.traverse(&root_hash)  // all reachable blobs
```

## Layer Stack

```
┌─────────────────────────────────────┐
│           gently-cli                │  CLI interface
├─────────────────────────────────────┤
│          gently-brain               │  LLM, Claude, daemons
├──────────────┬──────────────────────┤
│  gently-spl  │    gently-ipfs      │  Tokens, IPFS
├──────────────┴──────────────────────┤
│          gently-core                │  Blobs, crypto, dance
└─────────────────────────────────────┘
```

## Model Chains

SVG containers hold WASM-compiled ML models:

```
model.svg
├── <svg>...</svg>           (visual)
├── refs:
│   ├── TAG_CODE → wasm_hash
│   ├── TAG_SCHEMA → schema_hash
│   ├── TAG_WEIGHTS → tensor_hash
│   └── TAG_NEXT → next_model_hash
```

Chained inference:
```
input → [embed] → [classify] → [output] → result
           │           │           │
           └───────────┴───────────┘
              TAG_NEXT links
```

## Security Model

### XOR Split-Knowledge

```
LOCK (stays on device)  ⊕  KEY (can be public)  =  SECRET
     │                         │                      │
     │                         │                      └── only exists
     │                         │                          during dance
     │                         └── stored anywhere
     └── NEVER transmitted
```

### Dance Protocol

Two-device verification:
1. Device A generates challenge
2. Device B responds with pattern
3. XOR reconstruction creates ephemeral secret
4. Secret used, then zeroed

### Permission Tree

```rust
struct PermissionTree {
    root: Hash,           // genesis hash
    nodes: Vec<PermissionNode>,
}

struct PermissionNode {
    hash: Hash,
    stake: u64,           // GNTLY staked
    permissions: HashSet<Permission>,
    children: Vec<Hash>,
}
```

51% stake = root control. Permissions cascade down tree.

## Git Chains

Content-addressed version control:

```rust
struct GitChain {
    store: BlobStore,
    branches: HashMap<String, Hash>,
    current: String,
}

// Commit = Manifest with:
TAG_PARENT  → previous commit
TAG_TREE    → knowledge snapshot
TAG_MESSAGE → commit metadata
```

## Watchdog

Event blobs for security monitoring:

```rust
struct Event {
    kind: EventKind,
    source: String,
    message: String,
    severity: u8,
    requires_inference: bool,
}

enum EventKind {
    Alert,
    Anomaly,
    Threshold,
    Integrity,
    Access,
    Inference,
}
```

Events requiring inference trigger LLM analysis.

## IPFS Pipeline

Batched blob sync to IPFS:

```
BlobStore ──put──► Pipeline ──batch──► IPFS
                       │
                       └── flush on interval/threshold
```

## Speed Optimizations

1. **Prefetch**: Load likely-next blobs during inference
2. **Batch Processing**: 32-64 vectors per cycle
3. **Connection Pooling**: Reuse IPFS connections
4. **Quantization**: INT8/INT4 for weights
5. **MoE Sparse Activation**: Only run needed experts

## Data Flow

```
User Input
    │
    ▼
┌─────────────┐
│ Orchestrator│───► Watchdog events
└─────┬───────┘
      │
      ▼
┌─────────────┐     ┌─────────────┐
│ Model Chain │────►│ IPFS Sync   │
└─────┬───────┘     └─────────────┘
      │
      ▼
┌─────────────┐
│ Knowledge   │───► Git Chain commits
│ Graph       │
└─────────────┘
```

## File Structure

```
gentlyos/
├── crates/
│   ├── gently-core/    # Blob store, crypto
│   ├── gently-spl/     # Tokens, NFTs
│   ├── gently-brain/   # LLM, daemons
│   ├── gently-ipfs/    # IPFS client
│   ├── gently-btc/     # Bitcoin anchoring
│   └── ...
├── gently-cli/         # CLI binary
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Key Modules

| Module | File | Purpose |
|--------|------|---------|
| Blob Store | `gently-core/src/blob.rs` | Content-addressable storage |
| Git Chain | `gently-brain/src/gitchain.rs` | Version control |
| Model Chain | `gently-brain/src/modelchain.rs` | SVG+WASM pipelines |
| Watchdog | `gently-brain/src/watchdog.rs` | Security events |
| Pipeline | `gently-brain/src/pipeline.rs` | IPFS sync |
| Dance | `gently-spl/src/dance.rs` | XOR verification |
| Tokens | `gently-spl/src/token.rs` | GNTLY/GOS/GENOS |
