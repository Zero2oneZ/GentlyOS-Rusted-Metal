# GentlyOS System Documentation
## Comprehensive Product Audit Report
**Generated**: 2026-01-02
**Version**: 0.1.0
**Genesis Hash**: `39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69`
**Genesis Time**: 2025-12-30T04:21:04Z
**Total Lines of Code**: ~28,678

---

## Table of Contents
1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Folder/File I/O Map](#3-folderfile-io-map)
4. [Crate Reference](#4-crate-reference)
5. [Genesis Configuration](#5-genesis-configuration)
6. [Security Model](#6-security-model)
7. [Known Oddities & Issues](#7-known-oddities--issues)
8. [Data Flow](#8-data-flow)

---

## 1. System Overview

GentlyOS is a content-addressable, token-governed operating system built in Rust. It combines:

- **XOR Split-Knowledge Security**: Secrets split as `LOCK XOR KEY = FULL_SECRET`
- **Content-Addressable Storage**: No files/folders, just SHA256 blobs
- **Token Economy**: GNTLY (governance), GOS (gas), GENOS (proof-of-thought)
- **72-Domain Semantic Router**: Thought indexing across semantic categories
- **Two-Device Dance Protocol**: Visual-audio handshake authentication
- **BTC-Anchored Audit Chain**: Immutable audit trail using Bitcoin block hashes
- **AI/ML Layer**: Claude API, Llama inference, knowledge graphs

### Core Principles

| Principle | Implementation |
|-----------|---------------|
| No plaintext secrets | XOR split-knowledge (Lock + Key = Secret) |
| No file paths | Content-addressable blobs (SHA256 identity) |
| No central authority | 51% stake governance via token holders |
| Immutable audit | BTC block hash anchoring |
| Cross-device trust | Dance handshake protocol |

---

## 2. Architecture Diagram

```
+-------------------------------------------------------------------+
|                          GENTLYOS v0.1.0                          |
+-------------------------------------------------------------------+
|                                                                   |
|  +-----------------+  +-----------------+  +-----------------+    |
|  |   gently-cli    |  | gently-architect|  |   gently-mcp    |    |
|  |  (40+ commands) |  |  (TUI + Flows)  |  | (Claude Server) |    |
|  +-----------------+  +-----------------+  +-----------------+    |
|          |                    |                    |              |
|  +-------v--------------------v--------------------v--------+     |
|  |                     INTEGRATION LAYER                    |     |
|  +----------------------------------------------------------+     |
|          |                    |                    |              |
|  +-------v--------+  +--------v-------+  +--------v--------+     |
|  |  gently-brain  |  |  gently-search |  |   gently-feed   |     |
|  | (AI/ML Engine) |  | (72-Domain Idx)|  | (Living Context)|     |
|  +----------------+  +----------------+  +-----------------+     |
|          |                    |                    |              |
|  +-------v--------------------v--------------------v--------+     |
|  |                      PROTOCOL LAYER                      |     |
|  +----------------------------------------------------------+     |
|          |                    |                    |              |
|  +-------v--------+  +--------v-------+  +--------v--------+     |
|  |  gently-dance  |  |  gently-cipher |  | gently-network  |     |
|  | (2-Device Auth)|  | (Crypto Tools) |  | (Packet Capture)|     |
|  +----------------+  +----------------+  +-----------------+     |
|          |                    |                    |              |
|  +-------v--------------------v--------------------v--------+     |
|  |                      STORAGE LAYER                       |     |
|  +----------------------------------------------------------+     |
|          |                    |                    |              |
|  +-------v--------+  +--------v-------+  +--------v--------+     |
|  |  gently-core   |  |   gently-ipfs  |  |   gently-spl    |     |
|  |  (Blobs/Vault) |  | (Content Addr) |  | (Token Economy) |     |
|  +----------------+  +----------------+  +-----------------+     |
|          |                    |                    |              |
|  +-------v--------------------v--------------------v--------+     |
|  |                    BLOCKCHAIN LAYER                      |     |
|  |  gently-btc (Audit Anchor) | gently-sploit (Security)   |     |
|  +----------------------------------------------------------+     |
|                                                                   |
+-------------------------------------------------------------------+
```

---

## 3. Folder/File I/O Map

### 3.1 Source Code Structure (`/root/gentlyos/`)

```
/root/gentlyos/
├── Cargo.toml                    # Workspace manifest (16 crates)
├── Dockerfile                    # Multi-stage build (~500MB runtime)
├── docker-compose.yml            # GentlyOS + IPFS services
├── target/
│   └── release/
│       └── gently                # Pre-built CLI binary (ELF 64-bit)
│
├── gently-cli/
│   ├── Cargo.toml                # CLI dependencies (26 crates)
│   └── src/
│       ├── main.rs               # ~52KB monolithic CLI (40+ commands)
│       └── report.rs             # Interactive TUI dashboard (ratatui)
│
└── crates/
    ├── gently-core/              # CRYPTOGRAPHIC FOUNDATION
    │   └── src/
    │       ├── lib.rs            # Public API exports
    │       ├── blob.rs           # Content-addressable storage
    │       ├── vault.rs          # Encrypted API key storage
    │       ├── pattern/
    │       │   ├── mod.rs        # Pattern engine
    │       │   ├── encoder.rs    # Pattern serialization
    │       │   └── primitives.rs # Basic pattern types
    │       └── crypto/
    │           ├── mod.rs        # Crypto module exports
    │           ├── xor.rs        # XOR split-knowledge (Lock/Key/FullSecret)
    │           ├── genesis.rs    # Genesis block generation
    │           └── derivation.rs # Key derivation functions
    │
    ├── gently-spl/               # TOKEN ECONOMY
    │   └── src/
    │       ├── lib.rs            # Public API
    │       ├── token.rs          # GNTLY, GOS, GENOS tokens
    │       ├── wallet.rs         # Wallet management
    │       ├── nft.rs            # NFT functionality
    │       ├── permissions.rs    # 7-tier permission system
    │       ├── governance.rs     # 51% stake voting
    │       ├── genos.rs          # Proof-of-thought tokens
    │       └── filesystem.rs     # Token-gated file access
    │
    ├── gently-brain/             # AI/ML ENGINE
    │   └── src/
    │       ├── lib.rs            # 19 module exports
    │       ├── agent.rs          # AI agent orchestration
    │       ├── claude.rs         # Claude API integration
    │       ├── llama.rs          # Local Llama inference
    │       ├── embedder.rs       # Text embeddings
    │       ├── knowledge.rs      # Knowledge graph
    │       ├── tensorchain.rs    # Tensor chain operations
    │       ├── download.rs       # Model downloads
    │       └── [daemon modules]  # Background daemons
    │
    ├── gently-dance/             # TWO-DEVICE HANDSHAKE
    │   └── src/
    │       ├── lib.rs            # Dance protocol
    │       ├── session.rs        # Session management
    │       ├── state.rs          # State machine
    │       ├── instruction.rs    # Dance instructions
    │       ├── contract.rs       # Protocol contracts
    │       └── backend.rs        # Audio/visual backend
    │
    ├── gently-feed/              # LIVING CONTEXT
    │   └── src/
    │       ├── lib.rs            # Feed system
    │       ├── feed.rs           # Main feed logic
    │       ├── item.rs           # Feed items with charge/decay
    │       ├── bridge.rs         # Feed bridges
    │       ├── extractor.rs      # Content extraction
    │       ├── xor_chain.rs      # XOR chain verification
    │       └── persistence.rs    # SQLite persistence
    │
    ├── gently-search/            # 72-DOMAIN SEMANTIC ROUTER
    │   └── src/
    │       ├── lib.rs            # Search system
    │       ├── router.rs         # 72-domain routing
    │       ├── domain.rs         # Domain definitions
    │       ├── thought.rs        # Thought indexing
    │       ├── index.rs          # Search indexes
    │       └── wormhole.rs       # Cross-domain linking
    │
    ├── gently-mcp/               # MODEL CONTEXT PROTOCOL
    │   └── src/
    │       ├── lib.rs            # MCP server
    │       ├── server.rs         # JSON-RPC 2.0 server
    │       ├── protocol.rs       # Protocol definitions
    │       ├── handler.rs        # Request handlers
    │       └── tools.rs          # Tool definitions
    │
    ├── gently-architect/         # VISUALIZATION + TUI
    │   └── src/
    │       ├── lib.rs            # Architect system
    │       ├── crystal.rs        # Crystal flow definitions
    │       ├── tree.rs           # Idea trees
    │       ├── flow.rs           # Flow diagrams
    │       ├── recall.rs         # Memory recall
    │       ├── security.rs       # Security visualization
    │       ├── render/
    │       │   ├── mod.rs        # Render module
    │       │   ├── ascii_tree.rs # ASCII tree rendering
    │       │   ├── ascii_flow.rs # ASCII flow rendering
    │       │   └── svg.rs        # SVG export
    │       └── tui/
    │           ├── mod.rs        # TUI module
    │           ├── app.rs        # Main TUI app
    │           ├── views/        # View components
    │           └── widgets/      # Widget components
    │
    ├── gently-cipher/            # CRYPTOGRAPHIC TOOLS
    │   └── src/
    │       ├── lib.rs            # Cipher toolkit
    │       ├── identifier.rs     # Algorithm identification
    │       ├── encodings.rs      # Base64, hex, etc.
    │       ├── ciphers.rs        # Encryption algorithms
    │       ├── hashes.rs         # Hash functions
    │       ├── analysis.rs       # Cryptanalysis
    │       ├── cracker.rs        # Password cracking
    │       └── rainbow.rs        # Rainbow tables
    │
    ├── gently-network/           # NETWORK SECURITY
    │   └── src/
    │       ├── lib.rs            # Network module
    │       ├── capture.rs        # Packet capture
    │       ├── firewall.rs       # Firewall rules
    │       ├── monitor.rs        # Traffic monitoring
    │       ├── visualizer.rs     # Network visualization
    │       ├── colors.rs         # Color coding
    │       └── mitm.rs           # MITM capabilities
    │
    ├── gently-sploit/            # SECURITY TESTING
    │   └── src/
    │       ├── lib.rs            # Exploit framework
    │       ├── exploits/
    │       │   ├── mod.rs        # Exploit modules
    │       │   ├── http.rs       # HTTP exploits
    │       │   ├── ssh.rs        # SSH exploits
    │       │   ├── smb.rs        # SMB exploits
    │       │   └── local.rs      # Local exploits
    │       └── payloads/
    │           └── mod.rs        # Payload generators
    │
    ├── gently-ipfs/              # CONTENT-ADDRESSABLE STORAGE
    │   └── src/
    │       ├── lib.rs            # IPFS integration
    │       ├── operations.rs     # Add/get/pin operations
    │       ├── pinning.rs        # Pin management
    │       └── mcp.rs            # MCP IPFS tools
    │
    ├── gently-btc/               # BITCOIN INTEGRATION
    │   └── src/
    │       └── lib.rs            # BTC utilities
    │
    ├── gently-audio/             # AUDIO PROCESSING
    │   └── src/
    │       └── lib.rs            # Audio I/O (cpal, dasp, rustfft)
    │
    ├── gently-visual/            # VISUAL PROCESSING
    │   └── src/
    │       └── lib.rs            # SVG generation
    │
    └── gently-py/                # PYTHON BINDINGS (DORMANT)
        └── src/
            └── lib.rs            # PyO3 bindings (placeholder)
```

### 3.2 Genesis Configuration (`/root/.gentlyos/`)

```
/root/.gentlyos/
├── genesis/
│   ├── genesis-hash.txt          # Root hash + timestamp
│   │   └── 39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69
│   │   └── GENESIS_TIME=2025-12-30T04:21:04Z
│   │
│   ├── ipfs-identity.json        # IPFS node identity
│   │   └── ID: 12D3KooWRJtYtVVS3VtU36Xu3HybhxEe4JMaEZXhD7JKG5PL3wH7
│   │   └── AgentVersion: kubo/0.27.0/
│   │
│   ├── btc-genesis.json          # BTC anchor data (large file)
│   │
│   ├── token.env                 # [ODDITY] Token address variant 1
│   │   └── GNTLY_OS=42di4pJntVc1e7caXLjSrqMLBd1voCiXkVa3G2QCnKJ7
│   │
│   ├── tokens.env                # [ODDITY] Token address variant 2
│   │   └── GNTLY_OS=13W59exEjUBAzcDt8wBwR5ge1KdbvGRqB167kbf5WNyV
│   │
│   └── binary-hashes.txt         # Binary verification hashes
│
├── audit.sh                      # BTC-anchored audit chain script
├── tm.sh                         # Token management script [HAS TYPO]
├── claude.sh                     # BTC-based branch switching wrapper
├── audit.log                     # Audit trail log
│
└── .git/                         # Git repository (7 branches)
    └── refs/heads/
        ├── master
        ├── branch-1
        ├── branch-2
        ├── branch-3
        ├── branch-4
        ├── branch-5
        ├── branch-6
        └── branch-7
```

### 3.3 I/O Characteristics by Crate

| Crate | Input | Output | Storage |
|-------|-------|--------|---------|
| gently-core | Raw bytes, keys | Blobs, encrypted vault | In-memory, IPFS |
| gently-spl | Token ops, wallet cmds | Transactions, balances | Solana blockchain |
| gently-brain | Text, embeddings | Inferences, knowledge | SQLite, IPFS |
| gently-dance | Audio/visual signals | Session tokens | In-memory |
| gently-feed | Content items | Charged feed items | SQLite |
| gently-search | Queries, thoughts | Indexed results | SQLite, 72 domains |
| gently-mcp | JSON-RPC requests | JSON-RPC responses | None (stateless) |
| gently-architect | Ideas, flows | ASCII/SVG diagrams | None |
| gently-cipher | Ciphertext | Plaintext, analysis | Rainbow tables |
| gently-network | Packets | Analysis, alerts | pcap files |
| gently-sploit | Target info | Exploit results | None |
| gently-ipfs | Files, CIDs | Pinned content | IPFS network |
| gently-btc | Block queries | Block hashes, heights | Bitcoin network |

---

## 4. Crate Reference

### 4.1 gently-core (Cryptographic Foundation)

**Purpose**: Content-addressable storage with XOR split-knowledge security.

**Key Types**:
```rust
// XOR Split-Knowledge
pub struct Lock(pub [u8; 32]);      // Half 1 of secret
pub struct Key(pub [u8; 32]);       // Half 2 of secret
pub struct FullSecret([u8; 32]);    // LOCK XOR KEY = FullSecret

// Content-Addressable Blobs
pub enum Kind {
    Raw, Wasm, Tensor, Manifest, Thought,
    Pattern, LoRA, Encrypted, Link, Split
}
pub struct BlobId(pub [u8; 32]);    // SHA256 hash identity
pub struct Blob { kind: Kind, data: Vec<u8> }

// Encrypted Storage
pub struct Vault { path: PathBuf, encryption_key: [u8; 32] }
```

**Public API**:
- `Blob::new(kind, data) -> Blob`
- `Blob::id() -> BlobId` (SHA256 of content)
- `Lock::generate() -> (Lock, Key)`
- `FullSecret::reconstruct(lock, key) -> FullSecret`
- `Vault::store(name, value)` / `Vault::retrieve(name)`

### 4.2 gently-spl (Token Economy)

**Purpose**: Three-token economy on Solana with 7-tier permissions.

**Token Types**:
| Token | Symbol | Purpose |
|-------|--------|---------|
| GentlyOS Token | GNTLY | Governance, 51% stake voting |
| Gas Token | GOS | Transaction fees |
| Genesis Token | GENOS | Proof-of-thought rewards |

**Permission Hierarchy**:
```
Root (51% stake) → Developer → Admin → System → Service → User → Guest
```

**Key Structures**:
```rust
pub struct GentlyToken { mint: Pubkey, decimals: u8, total_supply: u64 }
pub struct Wallet { keypair: Keypair, balances: HashMap<Pubkey, u64> }
pub struct Permission { level: PermissionLevel, scope: String, granted_by: Pubkey }
pub struct Proposal { id: u64, description: String, votes_for: u64, votes_against: u64 }
```

### 4.3 gently-brain (AI/ML Engine)

**Purpose**: AI inference layer with Claude API, Llama, and knowledge graphs.

**19 Modules**:
- `agent` - AI agent orchestration
- `claude` - Claude API client
- `llama` - Local Llama inference
- `embedder` - Text embeddings
- `knowledge` - Knowledge graph
- `daemon` - Background daemons (vector_chain, ipfs_sync, git_branch, awareness, inference)
- `evolve` - Model evolution via LoRA chains
- `skills` - Skill definitions
- `tensorchain` - Tensor chain operations
- `download` - Model downloads with progress

**Key Structures**:
```rust
pub struct Agent { id: String, model: ModelType, context: Context }
pub struct LoRAChain { adapters: Vec<LoRAAdapter>, base_model: String }
pub struct KnowledgeGraph { nodes: Vec<Node>, edges: Vec<Edge> }
pub struct Daemon { name: String, interval: Duration, handler: fn() }
```

### 4.4 gently-dance (Two-Device Handshake)

**Purpose**: Visual-audio handshake protocol for cross-device authentication.

**Protocol Flow**:
```
Device A                          Device B
   |                                 |
   |--- Generate ChallengeSeed ---->|
   |                                 |
   |<--- Visual Pattern Display -----|
   |                                 |
   |--- Audio Confirmation -------->|
   |                                 |
   |<--- Session Token -------------|
   |                                 |
```

**Key Structures**:
```rust
pub struct DanceSession { id: Uuid, state: DanceState, created: DateTime }
pub enum DanceState { Waiting, Challenged, Verifying, Complete, Failed }
pub struct DanceInstruction { pattern: VisualPattern, audio: AudioSignal }
```

### 4.5 gently-feed (Living Context)

**Purpose**: Feed system with charge/decay mechanics for context tracking.

**Charge States**:
```
HOT (100%) → ACTIVE (75%) → COOLING (50%) → FROZEN (25%) → ARCHIVED (0%)
```

**Key Structures**:
```rust
pub struct FeedItem { id: Uuid, content: String, charge: f64, created: DateTime }
pub struct Feed { items: Vec<FeedItem>, decay_rate: f64 }
pub struct XorChain { entries: Vec<XorEntry> }  // Verification chain
```

### 4.6 gently-search (72-Domain Semantic Router)

**Purpose**: Thought indexing across 72 semantic domains.

**Domain Assignment**: `domain = thought_hash % 72` (0-71)

**Key Structures**:
```rust
pub struct Thought { id: Uuid, content: String, domain: u8, embedding: Vec<f32> }
pub struct Domain { id: u8, name: String, thoughts: Vec<ThoughtId> }
pub struct Wormhole { from: Domain, to: Domain, strength: f64 }  // Cross-domain links
pub struct Router { domains: [Domain; 72] }
```

### 4.7 gently-mcp (Model Context Protocol)

**Purpose**: JSON-RPC 2.0 server for Claude integration.

**Available Tools**:
- `gently_blob_store` - Store blobs
- `gently_blob_retrieve` - Retrieve blobs
- `gently_search` - Search thoughts
- `gently_feed` - Feed operations
- `gently_dance` - Dance protocol
- `gently_ipfs_*` - IPFS operations

**Protocol**:
```json
{"jsonrpc": "2.0", "method": "tools/list", "id": 1}
{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "gently_search", "arguments": {...}}, "id": 2}
```

---

## 5. Genesis Configuration

### 5.1 Genesis Identity

| Property | Value |
|----------|-------|
| Genesis Hash | `39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69` |
| Genesis Time | `2025-12-30T04:21:04Z` |
| IPFS Node ID | `12D3KooWRJtYtVVS3VtU36Xu3HybhxEe4JMaEZXhD7JKG5PL3wH7` |
| IPFS Agent | `kubo/0.27.0/` |

### 5.2 Token Addresses

**ODDITY**: Two different addresses exist for GNTLY_OS token:

| File | Address |
|------|---------|
| `token.env` | `42di4pJntVc1e7caXLjSrqMLBd1voCiXkVa3G2QCnKJ7` |
| `tokens.env` | `13W59exEjUBAzcDt8wBwR5ge1KdbvGRqB167kbf5WNyV` |

**Resolution Required**: Determine which is the canonical token address.

### 5.3 BTC-Anchored Audit Chain

The audit system uses Bitcoin block hashes for immutable timestamping:

```
AUDIT_HASH = SHA256(PREV_HASH + COMMAND + BTC_BLOCK_HASH + TIMESTAMP)
```

**audit.sh Flow**:
1. Fetch current BTC block height and hash
2. Read previous audit hash (or genesis hash)
3. Concatenate: `prev_hash + command + btc_block + timestamp`
4. SHA256 hash the concatenation
5. Append to audit.log: `hash|btc_height|timestamp|command`

### 5.4 Branch Rotation (claude.sh)

BTC block height determines which branch to use:
```
branch_number = (btc_height % 7) + 1  // Results in branch-1 through branch-7
```

---

## 6. Security Model

### 6.1 XOR Split-Knowledge

```
┌─────────────────────────────────────────────────────┐
│                   FULL SECRET                       │
│  (Never stored in plaintext, only in memory)        │
└─────────────────────────────────────────────────────┘
                         │
                    XOR SPLIT
                    ┌────┴────┐
                    ▼         ▼
              ┌─────────┐ ┌─────────┐
              │  LOCK   │ │   KEY   │
              │(Device A)│ │(Device B)│
              └─────────┘ └─────────┘
                    │         │
                    └────┬────┘
                    XOR COMBINE
                         ▼
              ┌─────────────────────┐
              │    FULL SECRET      │
              │  (Reconstructed)    │
              └─────────────────────┘
```

**Properties**:
- Neither LOCK nor KEY reveals anything about the secret alone
- Both halves required for reconstruction
- Keys zeroized from memory after use (`zeroize` crate)

### 6.2 Content-Addressable Integrity

```
Content → SHA256 → BlobId (32 bytes)
```

- Content cannot be modified without changing its identity
- Duplicate content automatically deduplicated
- Integrity verified on every retrieval

### 6.3 Token-Gated Access

```
┌──────────────────────────────────────────────────┐
│                PERMISSION CHECK                   │
├──────────────────────────────────────────────────┤
│ 1. User presents wallet signature                │
│ 2. System checks GNTLY balance                   │
│ 3. Permission level derived from stake %         │
│ 4. Access granted/denied based on required level │
└──────────────────────────────────────────────────┘
```

### 6.4 Audit Immutability

```
Genesis → Audit₁ → Audit₂ → ... → Auditₙ
   │         │         │              │
   └─── Each hash includes BTC block ─┘
        (Cannot be forged retroactively)
```

---

## 7. Known Oddities & Issues

### 7.1 Critical Issues

| ID | Location | Issue | Impact |
|----|----------|-------|--------|
| ODD-001 | `/root/.gentlyos/tm.sh:7` | **TYPO**: `balace` should be `balance` | Token balance check fails |
| ODD-002 | `/root/.gentlyos/genesis/` | **DUPLICATE TOKEN FILES**: `token.env` and `tokens.env` have different addresses | Ambiguous canonical token |
| ODD-003 | `/root/.gentlyos/claude.sh:5` | **SYNTAX ERROR**: Missing quote in git checkout command | Script fails on execution |

### 7.2 Implementation Gaps

| ID | Crate | Issue | Status |
|----|-------|-------|--------|
| GAP-001 | gently-ipfs | **MOCK IMPLEMENTATION**: Uses fake CIDs, no real IPFS connection | Needs real IPFS integration |
| GAP-002 | gently-brain | **STUBS**: ONNX/GGUF inference simulated, returns placeholder vectors | Needs real inference |
| GAP-003 | gently-dance | **INCOMPLETE**: `DanceInitiate` and `IdentityVerify` are empty stubs | Protocol not functional |
| GAP-004 | gently-sploit | **EDUCATIONAL ONLY**: Exploits are demonstrations, not real attacks | By design |
| GAP-005 | gently-py | **DORMANT**: Python bindings crate exists but is empty | Needs implementation |

### 7.3 Documentation Gaps

| ID | Issue | Resolution |
|----|-------|------------|
| DOC-001 | 72-domain semantic meaning undocumented | Document what each domain (0-71) represents |
| DOC-002 | Dance protocol handshake steps unclear | Write protocol specification |
| DOC-003 | Token economics (GNTLY/GOS/GENOS) not fully specified | Define token utility and distribution |
| DOC-004 | Charge/decay rates for feed items undefined | Specify decay algorithm |

### 7.4 Environment Issues

| ID | Issue | Resolution |
|----|-------|------------|
| ENV-001 | `/bin/sh` symlink missing | Run `ln -s /bin/busybox /bin/sh` |
| ENV-002 | `SHELL` environment variable unset | Export `SHELL=/bin/busybox` |
| ENV-003 | BusyBox minimal environment | Alpine/BusyBox container lacks full POSIX shell |

### 7.5 Security Considerations

| ID | Crate | Consideration |
|----|-------|---------------|
| SEC-001 | gently-cipher | Rainbow table cracking capability - authorized use only |
| SEC-002 | gently-network | MITM capabilities - requires explicit authorization |
| SEC-003 | gently-sploit | Exploit framework - for security testing only |
| SEC-004 | gently-core | API keys stored in vault - encryption key management critical |

---

## 8. Data Flow

### 8.1 Content Storage Flow

```
User Input
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ gently-cli  │────▶│ gently-core │────▶│ gently-ipfs │
│  (command)  │     │  (blob)     │     │   (CID)     │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          ▼
                    ┌─────────────┐
                    │gently-search│
                    │ (72 domains)│
                    └─────────────┘
```

### 8.2 Authentication Flow

```
Device A                              Device B
    │                                     │
    │  1. Generate Lock                   │
    ▼                                     ▼
┌─────────────┐                     ┌─────────────┐
│gently-dance │◀───────────────────▶│gently-dance │
│ (visual)    │   2. Visual QR      │  (audio)    │
└─────────────┘                     └─────────────┘
    │                                     │
    │  3. Audio confirm                   │
    ▼                                     ▼
┌─────────────┐                     ┌─────────────┐
│ gently-spl  │◀───────────────────▶│ gently-spl  │
│  (verify)   │   4. Token verify   │  (wallet)   │
└─────────────┘                     └─────────────┘
    │
    ▼
Session Established
```

### 8.3 AI Inference Flow

```
Query
    │
    ▼
┌─────────────┐
│gently-search│──── Domain routing (0-71)
└─────────────┘
    │
    ▼
┌─────────────┐
│gently-brain │──── Claude API / Llama
└─────────────┘
    │
    ▼
┌─────────────┐
│ gently-feed │──── Context charging
└─────────────┘
    │
    ▼
┌─────────────┐
│gently-ipfs  │──── Knowledge persistence
└─────────────┘
    │
    ▼
Response + GENOS reward
```

### 8.4 Audit Trail Flow

```
Command Execution
    │
    ▼
┌─────────────┐     ┌─────────────┐
│  audit.sh   │────▶│ gently-btc  │
│  (log)      │     │ (block hash)│
└─────────────┘     └─────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│ HASH = SHA256(prev + cmd + btc + ts) │
└──────────────────────────────────────┘
    │
    ▼
audit.log: hash|height|timestamp|command
```

---

## Appendix A: CLI Command Reference

The `gently` CLI binary supports 40+ commands organized into groups:

| Group | Commands |
|-------|----------|
| Blob | `blob store`, `blob get`, `blob list` |
| Vault | `vault store`, `vault get`, `vault list`, `vault delete` |
| Token | `token balance`, `token transfer`, `token mint` |
| Dance | `dance init`, `dance verify`, `dance status` |
| Feed | `feed add`, `feed list`, `feed charge`, `feed decay` |
| Search | `search query`, `search domain`, `search wormhole` |
| Brain | `brain query`, `brain embed`, `brain daemon` |
| IPFS | `ipfs add`, `ipfs get`, `ipfs pin`, `ipfs unpin` |
| Cipher | `cipher encode`, `cipher decode`, `cipher crack` |
| Network | `network capture`, `network analyze`, `network firewall` |
| Architect | `architect tree`, `architect flow`, `architect tui` |
| MCP | `mcp server`, `mcp client` |

---

## Appendix B: Dependency Graph

```
gently-cli
├── gently-core
├── gently-spl ──────────▶ gently-core
├── gently-brain ────────▶ gently-core, gently-ipfs
├── gently-dance ────────▶ gently-core, gently-audio, gently-visual
├── gently-feed ─────────▶ gently-core
├── gently-search ───────▶ gently-core, gently-brain
├── gently-mcp ──────────▶ gently-core, gently-ipfs
├── gently-architect ────▶ gently-core
├── gently-cipher ───────▶ (standalone)
├── gently-network ──────▶ (standalone)
├── gently-sploit ───────▶ gently-network
├── gently-ipfs ─────────▶ gently-core
├── gently-btc ──────────▶ (standalone)
├── gently-audio ────────▶ (standalone)
└── gently-visual ───────▶ (standalone)
```

---

**Document Version**: 1.0.0
**Last Updated**: 2026-01-02
**Maintainer**: GentlyOS Team
