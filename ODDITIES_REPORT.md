# GentlyOS Oddities & Issues Report
## Audit Findings Requiring Resolution

**Generated**: 2026-01-02
**Updated**: 2026-01-03 (Audit session)
**Severity Levels**: CRITICAL | HIGH | MEDIUM | LOW

---

## Summary

| Severity | Count | Fixed | Remaining |
|----------|-------|-------|-----------|
| CRITICAL | 3 | 0 | 3 |
| HIGH | 5 | 0 | 5 |
| MEDIUM | 4 | 0 | 4 |
| LOW | 3 | 0 | 3 |
| **BUILD** | **10** | **8** | **2** |
| **TOTAL** | **25** | **8** | **17** |

### 2026-01-03 Session Updates

**Build blockers resolved (see AUDIT_COMPLETION_REPORT.md)**:
- gently-feed: Added sha2, rand deps + derive macros
- gently-search: Added sha2 dep + WormholeDetector derives + router fix
- gently-network: Fixed temporary borrow + added Serialize/Deserialize
- gently-brain: Fixed raw string delimiter + temporary borrows (20 errors remain)
- Workspace: Added gently-security, gently-gateway (excluded gently-spl, gently-py)

---

## CRITICAL Issues

### ODD-001: Token Management Script Typo
**File**: `/root/.gentlyos/tm.sh:7`
**Issue**: Command `balace` should be `balance`
**Impact**: Token balance queries fail silently

**Current Code**:
```bash
balance) spl-token balace $GNTLY_OS ;;
```

**Fix**:
```bash
balance) spl-token balance $GNTLY_OS ;;
```

---

### ODD-002: Token Configuration File Mismatch
**Files**:
- `/root/.gentlyos/genesis/token.env` - Manual placeholder (STALE)
- `/root/.gentlyos/genesis/tokens.env` - Actual minted token (CURRENT)

**Analysis** (from shell history):
```
# token.env was manually created first (placeholder):
echo "GNTLY_OS=42di4pJntVc1e7caXLjSrqMLBd1voCiXkVa3G2QCnKJ7" > token.env

# tokens.env was created later when actually minting:
spl-token create-token --decimals 9 --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
echo "GNTLY_OS=$T" > tokens.env
```

**Issue**: `tm.sh` sources `token.env` (the STALE placeholder), not `tokens.env` (the REAL token)

| File | Address | Status |
|------|---------|--------|
| token.env | `42di4pJntVc1e7caXLjSrqMLBd1voCiXkVa3G2QCnKJ7` | STALE - placeholder |
| tokens.env | `13W59exEjUBAzcDt8wBwR5ge1KdbvGRqB167kbf5WNyV` | CURRENT - minted token |

**Impact**: Token management script uses wrong token address

**Resolution Required**:
1. Update `tm.sh` line 2: `TOKENS=/root/.gentlyos/genesis/tokens.env` (add 's')
2. Remove or archive `token.env` to prevent confusion
3. Or consolidate to single file

---

### ODD-003: Claude Wrapper Script Syntax Error
**File**: `/root/.gentlyos/claude.sh:5`
**Issue**: Malformed git checkout command with misplaced quote

**Current Code**:
```bash
git -C /root/.gentlyos checkout branch-$BRANCH:btc-$BTC"
```

**Fix**:
```bash
git -C /root/.gentlyos checkout "branch-$BRANCH"
```

---

## HIGH Priority Issues

### GAP-001: IPFS Mock Implementation
**Crate**: `gently-ipfs`
**Issue**: Uses fake/mock CIDs, no real IPFS connection
**Files Affected**:
- `crates/gently-ipfs/src/operations.rs`
- `crates/gently-ipfs/src/pinning.rs`

**Evidence**: Operations return hardcoded/simulated CIDs instead of connecting to IPFS node

**Resolution**: Implement real IPFS integration using `ipfs-api-backend-hyper`

---

### GAP-002: Brain Module Inference Stubs
**Crate**: `gently-brain`
**Issue**: ONNX/GGUF inference returns placeholder vectors, not real embeddings
**Files Affected**:
- `crates/gently-brain/src/llama.rs`
- `crates/gently-brain/src/embedder.rs`

**Impact**: AI features non-functional

**Resolution**:
1. Implement real GGUF model loading via `llama.cpp` bindings
2. Implement ONNX runtime for embedding models
3. Add model download verification

---

### GAP-003: Dance Protocol Empty Stubs
**Crate**: `gently-dance`
**Issue**: Core protocol functions are empty stubs
**Functions Affected**:
- `DanceInitiate` - Returns placeholder
- `IdentityVerify` - Returns placeholder

**Impact**: Two-device authentication non-functional

**Resolution**: Implement full dance protocol:
1. Visual QR pattern generation
2. Audio confirmation signal
3. Challenge-response verification
4. Session token generation

---

### ENV-001: Missing Shell Symlink
**Location**: `/bin/sh`
**Issue**: Symlink to shell missing in container environment
**Evidence**: `/bin/busybox` exists but `/bin/sh` doesn't

**Impact**: All shell scripts fail, CLI commands unavailable

**Resolution**:
```bash
ln -s /bin/busybox /bin/sh
export SHELL=/bin/sh
```

---

### ENV-002: SHELL Environment Variable Unset
**Issue**: `$SHELL` environment variable not configured
**Impact**: Subprocess spawning fails

**Resolution**: Add to container entrypoint or profile:
```bash
export SHELL=/bin/sh
```

---

## MEDIUM Priority Issues

### GAP-004: Sploit Module Educational Only
**Crate**: `gently-sploit`
**Issue**: Exploits are demonstrations/simulations, not functional
**Status**: **BY DESIGN** - for security education

**Note**: This is intentional for safety. Document accordingly.

---

### GAP-005: Python Bindings Dormant
**Crate**: `gently-py`
**Issue**: PyO3 bindings crate exists but contains no actual bindings
**File**: `crates/gently-py/src/lib.rs`

**Impact**: Python integration unavailable

**Resolution**: Implement PyO3 bindings for core functionality or remove crate

---

### DOC-001: 72-Domain Semantic Meaning Undocumented
**Crate**: `gently-search`
**Issue**: Domain assignment uses `hash % 72` but meaning of each domain not specified

**Example Questions**:
- What is domain 0 vs domain 71?
- Are domains named (e.g., "Technology", "Philosophy")?
- How should users interpret domain routing?

**Resolution**: Document all 72 domains with semantic meanings

---

### DOC-002: Token Economics Unspecified
**Crate**: `gently-spl`
**Issue**: GNTLY/GOS/GENOS relationship and economics not fully specified

**Missing Specifications**:
- Token distribution schedule
- GOS gas cost per operation
- GENOS reward calculations
- 51% governance threshold calculations

**Resolution**: Create token economics whitepaper

---

## LOW Priority Issues

### DOC-003: Charge/Decay Rates Undefined
**Crate**: `gently-feed`
**Issue**: Feed item decay algorithm not specified

**Questions**:
- What is the decay rate per hour/day?
- How does charge affect retrieval priority?
- Can items be recharged?

---

### DOC-004: Dance Protocol Steps Unclear
**Crate**: `gently-dance`
**Issue**: Handshake protocol not formally specified

**Missing**:
- Sequence diagram
- Timing requirements
- Error handling states

---

### SEC-001: Security Module Authorization
**Crates**: `gently-cipher`, `gently-network`, `gently-sploit`
**Issue**: Security testing tools available without authorization checks

**Recommendation**: Add explicit authorization prompts or logging for:
- Rainbow table cracking
- MITM operations
- Exploit execution

---

## Product Claude CLI Architecture

### Overview

GentlyOS has its own Claude integration separate from development tools:

```
PRODUCT LEVEL (for customers):
├── gently-brain/src/claude.rs    # Rust Claude API client
├── gently-cli/src/main.rs        # CLI: gently claude {chat|ask|repl|status}
└── ~/.gentlyos/claude.sh         # BTC-audited wrapper script

DEVELOPMENT LEVEL (for building GentlyOS):
└── ~/.claude.json                # Anthropic Claude Code config (NOT product code)
```

### Product Claude Commands

| Command | Description |
|---------|-------------|
| `gently claude chat "msg"` | Conversational chat with history |
| `gently claude ask "question"` | One-off question (no history) |
| `gently claude repl` | Interactive REPL session |
| `gently claude status` | Check API key and connection |

### Model Support

| Model | API Name | Notes |
|-------|----------|-------|
| Sonnet 4 | `claude-sonnet-4-20250514` | Default, balanced |
| Opus 4 | `claude-opus-4-0-20250514` | Most capable |
| Haiku 3.5 | `claude-3-5-haiku-20241022` | Fastest |

### claude.sh Wrapper (BTC-Audited)

The `claude.sh` wrapper adds audit trail to Claude invocations:
1. Fetches current BTC block height
2. Switches to branch-(height % 7 + 1)
3. Logs audit entry: `claude_start:branch:btc-{height}`
4. Invokes Claude
5. Logs audit entry: `claude_end:branch-{n}:btc-{height}`
6. Returns to master branch

**Note**: Has syntax error on line 5 (see ODD-003)

---

## Shell Environment Requirements

### Required Binaries

| Binary | Purpose | Package |
|--------|---------|---------|
| `/bin/sh` | POSIX shell for scripts | busybox symlink |
| `curl` | HTTP requests | curl |
| `jq` | JSON processing | jq |
| `sha256sum` | Hash computation | coreutils |
| `git` | Version control | git |
| `spl-token` | Solana token ops | solana-cli |
| `date` | Timestamps | coreutils |

### Container Fix

```bash
# Create shell symlink
ln -s /bin/busybox /bin/sh

# Set environment
export SHELL=/bin/sh

# Verify
ls -la /bin/sh
$SHELL --version
```

### Scripts Requiring Shell

| Script | Purpose |
|--------|---------|
| `audit.sh` | BTC-anchored audit chain |
| `tm.sh` | Token management |
| `claude.sh` | Audited Claude wrapper |

---

## Action Items Checklist

### Build Issues (from 2026-01-03 audit)
- [x] Fix gently-feed missing dependencies (sha2, rand)
- [x] Add Debug/Clone derives to ContextExtractor, BridgeDetector
- [x] Fix gently-search missing sha2 dependency
- [x] Add Debug/Clone derive to WormholeDetector
- [x] Fix gently-search router.rs Pattern trait issue
- [x] Fix gently-network capture.rs temporary borrow
- [x] Add Serialize/Deserialize to ScopeRule, Protocol
- [x] Fix gently-brain raw string delimiter (r#" to r##")
- [x] Fix gently-brain claude.rs temporary borrows
- [ ] Fix gently-brain remaining 20 API/type mismatches

### Shell Scripts
- [ ] Fix `balace` typo in `tm.sh:7`
- [ ] Update `tm.sh` to use `tokens.env` (not `token.env`)
- [ ] Fix syntax error in `claude.sh:5`
- [ ] Add shell symlink to container entrypoint
- [ ] Set SHELL environment variable in container

### Features
- [ ] Implement real IPFS integration
- [ ] Implement real brain inference
- [ ] Complete dance protocol implementation

### Documentation
- [ ] Document 72 semantic domains
- [ ] Write token economics specification
- [ ] Specify charge/decay algorithm
- [ ] Create dance protocol specification
- [ ] Add authorization for security tools

---

## Verification Commands

Once shell is available, run these to verify fixes:

```bash
# Verify shell fix
which sh && echo "Shell OK"

# Test token management
/root/.gentlyos/tm.sh balance

# Test audit chain
/root/.gentlyos/audit.sh test_command

# Test CLI
/root/gentlyos/target/release/gently --help
```

---

**Report Version**: 1.0.0
**Reviewed By**: Automated Audit
