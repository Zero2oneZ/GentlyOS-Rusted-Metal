# GentlyOS - Claude Context

**Last Updated**: 2026-01-02
**Lines of Code**: ~30,000+
**Crates**: 17 Rust crates + Solana program

---

## Current State

### Just Completed: gently-guardian crate

Free tier "Guardian" node that earns GNTLY tokens by contributing compute:

```
crates/gently-guardian/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Guardian manager, NodeTier enum, GuardianConfig
│   ├── main.rs          # CLI: start, register, benchmark, status, claim, upgrade
│   ├── hardware.rs      # Linux hardware detection, fingerprinting, scoring
│   ├── benchmark.rs     # CPU/Memory/GPU/Storage benchmarks, proof-of-work
│   ├── contribution.rs  # Work queue, task processing, merkle proofs
│   ├── rewards.rs       # Solana RPC simulation, reward tracking, tier upgrades
│   └── anti_cheat.rs    # Hardware validation, Sybil detection, VM detection
```

### Solana Reward Program

```
contracts/solana/programs/gently-rewards/src/lib.rs
```

Anchor-based program with:
- `initialize_pool` - Create reward pool
- `register_node` - Register guardian with hardware hash
- `submit_contribution` - Submit work proofs
- `claim_rewards` - Claim earned GNTLY
- `upgrade_tier` - Stake to upgrade (Guardian -> Home -> Business -> Studio)
- `slash_node` - Penalize cheaters

---

## Build Commands

```bash
# Build guardian crate (VERIFY THIS FIRST)
cargo build --release -p gently-guardian

# Build full workspace
cargo build --release

# Run guardian node
./target/release/gently-guardian start

# Run benchmark only
./target/release/gently-guardian benchmark
```

---

## Architecture

### Node Tiers

| Tier | Stake | Features |
|------|-------|----------|
| Guardian | Free | Earn by contributing compute |
| Home | 1,000 GNTLY | Priority routing, 2x rewards |
| Business | 5,000 GNTLY | Dedicated capacity, 3x rewards |
| Studio | 25,000 GNTLY | GPU protection, 5x rewards |

### Reward Algorithm

```
reward = 0.01 × hardware_score × uptime_multiplier × quality_score

hardware_score = CPU_cores + RAM_GB/4 + GPU_VRAM*5 + Storage_GB/100
uptime_multiplier = min(hours/24, 1.0) × tier_bonus
quality_score = tasks_completed / (tasks_completed + tasks_failed)
```

### Anti-Cheat Checks

1. CPU hash rate vs claimed cores
2. Memory bandwidth vs claimed speed
3. GPU inference time vs VRAM
4. Proof-of-work validity (2 leading zero bytes)
5. Timestamp freshness (<10 min)
6. Fingerprint uniqueness (Sybil detection)
7. Performance consistency over time

---

## Deployment Infrastructure (v1.1.1)

Created in `scripts/deploy/`:
- `build-all.sh` - Master build script
- `build-docker.sh` - Docker image
- `build-iso.sh` - Bootable ISO (Kali-style)
- `build-virtualbox.sh` - OVA appliance
- `build-deb.sh` - Debian package + systemd
- `build-termux.sh` - Android/Termux

Web assets in `web/`:
- `download/index.html` - Download page with 3 tiers
- `install.sh` - One-liner installer

---

## 17 Crates Overview

| Crate | Purpose |
|-------|---------|
| gently-core | Base types, config |
| gently-btc | Bitcoin RPC, block anchoring |
| gently-spl | Solana SPL token integration |
| gently-dance | P2P dance protocol |
| gently-audio | Audio processing, TTS |
| gently-visual | SVG generation, visualization |
| gently-feed | RSS/content feeds |
| gently-search | Vector search, embeddings |
| gently-mcp | Model Context Protocol |
| gently-architect | Code generation |
| gently-brain | LLM orchestration, daemons |
| gently-network | Network security, MITM |
| gently-ipfs | IPFS integration |
| gently-cipher | Crypto utilities, hashing |
| gently-sploit | Security tools |
| gently-gateway | API gateway, routing |
| gently-security | 16 security daemons |
| gently-guardian | **NEW** - Free tier node |

---

## Security Daemon Layers

```
Layer 1 (Foundation): HashChainValidator, BtcAnchor, ForensicLogger
Layer 2 (Traffic): TrafficSentinel, TokenWatchdog, CostGuardian
Layer 3 (Detection): PromptAnalyzer, BehaviorProfiler, PatternMatcher, AnomalyDetector
Layer 4 (Defense): SessionIsolator, TarpitController, ResponseMutator, RateLimitEnforcer
Layer 5 (Intel): ThreatIntelCollector, SwarmDefense
```

---

## Next Steps

1. **Verify build**: `cargo build --release -p gently-guardian`
2. Fix any compile errors
3. Test guardian CLI commands
4. Integrate with gently-cli main binary
5. Deploy to test network

---

## Product Vision

Three editions:
- **Home** (Free/Guardian) - Security as public good, earn by contributing
- **Business** ($29/mo) - Priority support, dedicated capacity
- **Studio** ($99/mo) - GPU protection, maximum security

"Trojan that helps" - Spreads protection, not infection.

---

## Key Files to Know

- `/root/gentlyos/Cargo.toml` - Workspace definition
- `/root/gentlyos/gently-cli/src/main.rs` - Main CLI
- `/root/gentlyos/crates/gently-brain/src/daemon.rs` - Daemon manager
- `/root/gentlyos/crates/gently-security/src/agentic.rs` - Security controller
- `/root/gentlyos/crates/gently-guardian/src/lib.rs` - Guardian node

---

## Environment

- Alpine Linux (bare metal)
- Rust toolchain
- No shell access from Claude (SSH needed)
- Git repo on main branch

---

*This file exists so Claude can recover context if session is lost.*
