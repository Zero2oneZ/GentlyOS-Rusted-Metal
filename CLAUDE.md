# GentlyOS - Claude Context

**Last Updated**: 2026-01-05
**Lines of Code**: ~75,000+
**Crates**: 22 Rust crates + TUI (Solana disabled)

---

## What Claude Code Built (2026-01-05)

### Inference Quality Mining (Session 3)

Collective Inference Optimization - The network trains itself through USE.

| File | Lines | Purpose |
|------|-------|---------|
| `gently-inference/src/step.rs` | 200 | InferenceStep, StepType (8 types) |
| `gently-inference/src/score.rs` | 200 | Quality scoring formula |
| `gently-inference/src/decompose.rs` | 250 | Response → Steps extraction |
| `gently-inference/src/cluster.rs` | 300 | Semantic clustering (cosine sim) |
| `gently-inference/src/aggregate.rs` | 250 | Cross-prompt step aggregation |
| `gently-inference/src/optimize.rs` | 300 | Response synthesis |
| `gently-inference/src/boneblob.rs` | 250 | BONEBLOB constraint generation |
| `gently-inference/src/solana.rs` | 250 | GENOS rewards (stubbed) |

#### The Quality Formula

```
quality = user_accept * 0.3
        + outcome_success * 0.4
        + chain_referenced * 0.2
        + turning_point * 0.1

THRESHOLD: 0.7 = USEFUL
```

#### Step Types

| Type | GENOS Multiplier | Purpose |
|------|-----------------|---------|
| Conclude | 12x | Research synthesis |
| Pattern | 10x | Creative insight |
| Eliminate | 8x | BONEBLOB contribution |
| Specific | 6x | Implementation detail |
| Fact | 5x | Verified data |
| Suggest | 4x | Ideas |
| Correct | 3x | Bug fixes |
| Guess | 1x | Low until validated |

#### BONEBLOB Integration

```
High-quality (>=0.7) → BONES (constraints)
    Eliminate → "MUST NOT: {content}"
    Fact      → "ESTABLISHED: {content}"
    Pattern   → "PATTERN: {content}"

Low-quality (<0.7) → CIRCLE (eliminations)
    Guess/Suggest → "AVOID: {content}"
```

#### Storage

```
~/.gently/inference/
├── inferences.jsonl      # Query + response records
├── steps.jsonl           # Individual reasoning steps
├── clusters.json         # Semantic clustering state
└── pending_genos.jsonl   # GENOS reward queue
```

---

### FAFO Security + Berlin Clock (Session 2)

"A rabid pitbull behind a fence" - Aggressive defense with time-based key rotation.

| File | Lines | Purpose |
|------|-------|---------|
| `gently-core/src/crypto/berlin.rs` | 380 NEW | BTC-synced time-based key rotation |
| `gently-security/src/fafo.rs` | 600 NEW | FAFO escalating response system |
| `gently-cli/src/main.rs` | +250 | `/security` command with dashboard |

#### Berlin Clock Key Rotation

```
BTC Block Timestamp → Slot (ts / 300) → HKDF → Time-Bound Key

Forward secrecy: Old slots cannot derive current keys
Sync: Any node with master + BTC time = same key
Grace period: 2 previous slots for decryption
```

#### FAFO Response Ladder

```
Strike 1-2:  TARPIT   - Waste attacker's time
Strike 3-4:  POISON   - Corrupt attacker's context
Strike 5-7:  DROWN    - Flood with honeypot garbage
Strike 10+:  DESTROY  - Permanent termination
CRITICAL:    SAMSON   - Scorched earth (nuclear option)
```

#### CLI Commands

```
gently security status   - Dashboard with FAFO stats
gently security fafo     - FAFO mode control
gently security daemons  - 16 security daemons status
gently security test     - Threat simulation
```

---

### BONEBLOB BIZ Constraint System (Session 1)

Philosophy → Compiler. Words became executable geometry.

```
BONE BLOB BIZ CIRCLE PIN
         ↓
constraint.rs + tesseract.rs
```

| File | Lines | Purpose |
|------|-------|---------|
| `gently-search/src/constraint.rs` | 325 NEW | Constraint optimization engine |
| `gently-alexandria/src/tesseract.rs` | +57 | BONEBLOB methods on 8-face hypercube |
| `gently-guardian/src/lib.rs` | +101 | Platform detection (macOS/Windows/Linux) |
| `gentlyos-tui/` | 5,693 NEW | Full terminal UI with BONEBLOB integration |

### The Math

```
Intelligence = Capability × Constraint / Search Space

BONES   → Preprompt constraints (immutable rules)
CIRCLE  → 70% elimination per pass (via negativa)
PIN     → Solution finder in bounded space
BIZ     → Solution → new constraint (fixed-point iteration)

Convergence: 5 passes × 70% elimination = 0.24% remaining
Guaranteed by Banach Fixed-Point Theorem
```

### Key Integration Points

1. **Tesseract `eliminated` face** (dims 48-95) stores "What it ISN'T"
2. **ConstraintBuilder** bridges Alexandria graph → BONEBLOB constraints
3. **72-domain router** feeds domain context to constraint system
4. **LlmWorker** optionally routes through BONEBLOB pipeline

### TUI Commands

```
/boneblob on|off  - Toggle constraint optimization
/boneblob         - Show pipeline status
/provider [name]  - Switch LLM (claude/gpt/deepseek/grok/ollama)
/status           - System + BONEBLOB stats
```

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
| gently-core | 98% | Crypto foundation, XOR splits, genesis keys, **Berlin Clock rotation** |
| gently-audio | 100% | FFT encoding/decoding with tests |
| gently-visual | 100% | SVG pattern generation |
| gently-dance | 85% | Full protocol state machine |
| gently-btc | 90% | Block promise logic |
| gently-ipfs | 85% | Thin wrapper (delegates to daemon) |
| gently-guardian | 80% | Hardware detection, cross-platform (sysinfo) |
| gently-security | 95% | 16/16 daemons, real hash chain, threat intel, **FAFO pitbull** |
| gently-feed | 70% | Charge/decay model works |
| gently-gateway | 70% | Pipeline architecture |
| gently-brain | 75% | Claude API real, Alexandria integration |
| gently-cipher | 50% | Ciphers work, analysis stubbed |
| gently-network | 60% | Visualization works |
| gently-architect | 55% | SQLite works, UI stubbed |
| gently-mcp | 50% | Server ready, handlers missing |
| gently-search | 80% | Alexandria routing, Tesseract projection, **BONEBLOB constraints** |
| gently-alexandria | 85% | Graph + Tesseract work, persistence, **elimination methods** |
| gently-sploit | 20% | Framework only |
| gently-sim | 80% | SIM card security: filesystem, applets, OTA, Simjacker |
| **gently-inference** | **90%** | **Inference quality mining: decompose, score, cluster, optimize** |
| gently-spl | DISABLED | Solana version conflicts |
| **gentlyos-tui** | **90%** | **Terminal UI: 6 panels, 7 LLM providers, BONEBLOB pipeline** |

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

## 22 Crates Overview

| Crate | Purpose |
|-------|---------|
| gently-core | Base types, genesis keys, XOR splits, Berlin Clock |
| gently-btc | Bitcoin RPC, block anchoring |
| gently-spl | Solana SPL (DISABLED) |
| gently-dance | P2P dance protocol |
| gently-audio | Audio FFT encoding |
| gently-visual | SVG pattern generation |
| gently-feed | Living feed with charge/decay |
| gently-search | Alexandria-backed semantic search, BONEBLOB |
| gently-mcp | Model Context Protocol server |
| gently-architect | Code generation, project trees |
| gently-brain | LLM orchestration, knowledge graph |
| gently-network | Network capture, MITM, visualization |
| gently-ipfs | IPFS content-addressed storage |
| gently-cipher | Cryptographic utilities, cracking |
| gently-sploit | Exploitation framework |
| gently-gateway | API routing, pipelines |
| gently-security | 16 daemons + FAFO pitbull |
| gently-guardian | Free tier node, hardware validation |
| gently-alexandria | Distributed knowledge mesh, Tesseract |
| gently-sim | SIM card security monitoring |
| **gently-inference** | **Inference quality mining + optimization** |

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
- `crates/gently-security/src/fafo.rs` - FAFO aggressive defense
- `crates/gently-guardian/src/hardware.rs` - Cross-platform hw detection

### Inference
- `crates/gently-inference/src/lib.rs` - InferenceEngine main API
- `crates/gently-inference/src/step.rs` - Step types and structures
- `crates/gently-inference/src/score.rs` - Quality scoring formula
- `crates/gently-inference/src/cluster.rs` - Semantic clustering
- `crates/gently-inference/src/boneblob.rs` - Constraint generation

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
