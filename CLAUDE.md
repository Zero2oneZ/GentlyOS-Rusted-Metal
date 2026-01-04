# GentlyOS - Claude Context

**Last Updated**: 2026-01-04
**Lines of Code**: ~35,000+
**Crates**: 17 Rust crates (Solana disabled)

---

## Current State (v1.0.0)

### Completed Sprints

| Sprint | Focus | Status |
|--------|-------|--------|
| 1 | Persistence + Embeddings | DONE |
| 2 | Intelligence Integration | DONE |
| 3 | Security Hardening | DONE |
| 4 | Distribution & Install | DONE |
| 5 | Polish & Stability | DONE |

### Production-Ready Crates

| Crate | Status | Notes |
|-------|--------|-------|
| gently-core | 95% | Crypto foundation, XOR splits, genesis keys |
| gently-audio | 100% | FFT encoding/decoding with tests |
| gently-visual | 100% | SVG pattern generation |
| gently-dance | 85% | Full protocol state machine |
| gently-btc | 90% | Block promise logic |
| gently-ipfs | 85% | Thin wrapper (delegates to daemon) |
| gently-guardian | 80% | Hardware detection, cross-platform (sysinfo) |
| gently-security | 85% | 16/16 daemons, real hash chain, threat intel |
| gently-feed | 70% | Charge/decay model works |
| gently-gateway | 70% | Pipeline architecture |
| gently-brain | 75% | Claude API real, Alexandria integration |
| gently-cipher | 50% | Ciphers work, analysis stubbed |
| gently-network | 60% | Visualization works |
| gently-architect | 55% | SQLite works, UI stubbed |
| gently-mcp | 50% | Server ready, handlers missing |
| gently-search | 70% | Alexandria routing, Tesseract projection |
| gently-alexandria | 75% | Graph + Tesseract work, persistence |
| gently-sploit | 20% | Framework only |
| gently-spl | DISABLED | Solana version conflicts |

---

## Installation

### One-Liner (Recommended)

```bash
curl -fsSL https://gentlyos.com/install.sh | sudo bash
```

Options:
- `--source` - Build from source instead of binary download
- `--skip-setup` - Skip the initial setup wizard

### First-Time Setup

```bash
gently setup           # Interactive wizard
gently setup --force   # Force re-initialization
```

Creates:
```
~/.gently/
├── alexandria/graph.json   # Knowledge graph
├── brain/knowledge.db      # SQLite knowledge base
├── feed/                   # Feed state
├── models/                 # Embedding models
├── vault/genesis.key       # Genesis key
└── config.toml             # User config
```

---

## Build Commands

```bash
# Build CLI (main binary)
cargo build --release -p gently-cli

# Build all crates
cargo build --release

# Run tests
cargo test --workspace

# Run CLI
./target/release/gently

# Run setup wizard
./target/release/gently setup
```

### Deployment Scripts

```bash
# Docker image
./scripts/deploy/build-docker.sh

# Debian package
./scripts/deploy/build-deb.sh

# All formats
./scripts/deploy/build-all.sh
```

---

## CLI Commands (28 total)

### Working (21)
```
init, create, pattern, split, combine, status, demo, feed,
search, alexandria, cipher, network, brain, architect, ipfs,
sploit, crack, claude, vault, mcp, report, setup
```

### Disabled (7 - Solana)
```
install, mint, wallet, token, certify, perm, genos
```

---

## Architecture

### Security Daemon Layers

```
Layer 1 (Foundation): HashChainValidator*, BtcAnchor, ForensicLogger
Layer 2 (Traffic):    TrafficSentinel, TokenWatchdog, CostGuardian
Layer 3 (Detection):  PromptAnalyzer, BehaviorProfiler, PatternMatcher, AnomalyDetector
Layer 4 (Defense):    SessionIsolator, TarpitController, ResponseMutator, RateLimitEnforcer
Layer 5 (Intel):      ThreatIntelCollector*, SwarmDefense

* = Real implementation (not stubbed)
```

### Hash Chain Validation

Real SHA256-linked audit chain:
- `AuditEntry` struct with index, timestamp, prev_hash, hash
- `HashChain::validate()` verifies chain integrity
- `HashChain::load/save()` for persistence
- Automatic tamper detection

### Threat Intel

Built-in LLM security patterns (28 indicators):
- Prompt injection detection ("ignore previous instructions", "DAN mode")
- System prompt extraction attempts
- Jailbreak patterns (roleplay, encoding tricks)
- Tool abuse patterns (file traversal, command injection)

---

## 17 Crates Overview

| Crate | Purpose |
|-------|---------|
| gently-core | Base types, genesis keys, XOR splits |
| gently-btc | Bitcoin RPC, block anchoring |
| gently-spl | Solana SPL (DISABLED) |
| gently-dance | P2P dance protocol |
| gently-audio | Audio FFT encoding |
| gently-visual | SVG pattern generation |
| gently-feed | Living feed with charge/decay |
| gently-search | Alexandria-backed semantic search |
| gently-mcp | Model Context Protocol server |
| gently-architect | Code generation, project trees |
| gently-brain | LLM orchestration, knowledge graph |
| gently-network | Network capture, MITM, visualization |
| gently-ipfs | IPFS content-addressed storage |
| gently-cipher | Cryptographic utilities, cracking |
| gently-sploit | Exploitation framework |
| gently-gateway | API routing, pipelines |
| gently-security | 16 security daemons |
| gently-guardian | Free tier node, hardware validation |
| gently-alexandria | Distributed knowledge mesh |

---

## Key Files

### Core
- `Cargo.toml` - Workspace definition
- `gently-cli/src/main.rs` - Main CLI (4000+ lines)
- `web/install.sh` - Universal installer

### Intelligence
- `crates/gently-alexandria/src/graph.rs` - Knowledge graph
- `crates/gently-alexandria/src/tesseract.rs` - 8-face embedding projection
- `crates/gently-brain/src/orchestrator.rs` - AI orchestration
- `crates/gently-search/src/alexandria.rs` - Semantic search

### Security
- `crates/gently-security/src/daemons/foundation.rs` - Hash chain
- `crates/gently-security/src/daemons/intel.rs` - Threat detection
- `crates/gently-guardian/src/hardware.rs` - Cross-platform hw detection

---

## Environment

- Alpine Linux (bare metal)
- Rust 1.75+ toolchain
- Docker available for container builds
- Git repo on master branch

---

## Product Vision

**Editions:**
- **Home** (Free/Guardian) - Security as public good, earn by contributing
- **Business** ($29/mo) - Priority support, dedicated capacity
- **Studio** ($99/mo) - GPU protection, maximum security

**Solana Integration** (deferred):
- Token/wallet/governance features remain stubbed
- Will be re-enabled after CLI v1.0 is stable

---

*This file exists so Claude can recover context if session is lost.*
