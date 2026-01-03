# GentlyOS BTC-Anchored Audit Architecture
## Session & Prompt/Response Hash Chain Specification

**Version**: 1.0.0
**Date**: 2026-01-02

---

## Overview

All user interactions with GentlyOS Claude integration must be cryptographically validated:

```
AUTH_KEY → PROMPT_HASH → RESPONSE_HASH → BTC_BLOCK_ANCHOR
```

Sessions are anchored to Bitcoin blocks at start and close, with real-time branch creation.

---

## Current State Analysis

### What EXISTS

| Component | File | Status |
|-----------|------|--------|
| Watchdog Event Log | `gently-brain/src/watchdog.rs` | Content-addressed events |
| GitChain | `gently-brain/src/gitchain.rs` | Branch management, commits |
| Audit Shell Script | `~/.gentlyos/audit.sh` | BTC block anchoring |
| Audit Log | `~/.gentlyos/audit.log` | Hash chain log |
| Claude Wrapper | `~/.gentlyos/claude.sh` | BTC-based branch switching |
| Claude API Client | `gently-brain/src/claude.rs` | API calls (no audit) |

### What's MISSING

| Component | Status | Priority |
|-----------|--------|----------|
| Auth key validation before prompts | NOT IMPLEMENTED | CRITICAL |
| Prompt content hashing | NOT IMPLEMENTED | CRITICAL |
| Response content hashing | NOT IMPLEMENTED | CRITICAL |
| Session start BTC anchor | PARTIAL (shell only) | HIGH |
| Session end BTC anchor | PARTIAL (shell only) | HIGH |
| Real-time branch creation | PARTIAL (shell only) | HIGH |
| Rust integration of BTC anchoring | NOT IMPLEMENTED | HIGH |
| Session-to-branch mapping | NOT IMPLEMENTED | MEDIUM |

---

## Target Architecture

### 1. Session Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                      SESSION LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  USER START                                                     │
│      │                                                          │
│      ▼                                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   SESSION_START                          │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │   │
│  │  │ AUTH_KEY    │──│ BTC_BLOCK_N  │──│ BRANCH_CREATE  │  │   │
│  │  │ validate    │  │ height+hash  │  │ branch-(N%7+1) │  │   │
│  │  └─────────────┘  └──────────────┘  └────────────────┘  │   │
│  │                            │                             │   │
│  │           SESSION_ID = SHA256(auth_key + btc_block)      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 PROMPT/RESPONSE LOOP                     │   │
│  │                                                          │   │
│  │   USER_PROMPT ──► PROMPT_HASH ──► CLAUDE_API            │   │
│  │                         │              │                 │   │
│  │                         │              ▼                 │   │
│  │                         │        RESPONSE_HASH           │   │
│  │                         │              │                 │   │
│  │                         ▼              ▼                 │   │
│  │   CHAIN_ENTRY = SHA256(prev_hash + prompt_hash +         │   │
│  │                        response_hash + timestamp)         │   │
│  │                                                          │   │
│  │   ┌──────────────────────────────────────────────────┐   │   │
│  │   │ COMMIT TO BRANCH                                 │   │   │
│  │   │ tree: {prompt_hash, response_hash, chain_entry}  │   │   │
│  │   │ message: "interaction-{seq}"                      │   │   │
│  │   └──────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    SESSION_END                           │   │
│  │  ┌──────────────┐  ┌───────────────┐  ┌───────────────┐  │   │
│  │  │ BTC_BLOCK_M  │──│ FINAL_CHAIN   │──│ MERGE_TO_MAIN │  │   │
│  │  │ height+hash  │  │ session_hash  │  │ (optional)    │  │   │
│  │  └──────────────┘  └───────────────┘  └───────────────┘  │   │
│  │                                                          │   │
│  │  SESSION_CLOSE_HASH = SHA256(session_id + btc_block_m +  │   │
│  │                               final_chain_hash)           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Hash Chain Structure

```
GENESIS_HASH (39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69)
      │
      ▼
SESSION_1_START
      │
      ├── interaction_1: prompt_hash + response_hash + btc_anchor
      │
      ├── interaction_2: prev_hash + prompt_hash + response_hash
      │
      └── interaction_N: ...
      │
      ▼
SESSION_1_END (btc_block_close)
      │
      ▼
SESSION_2_START (new btc_block, new branch)
      │
      ...
```

### 3. Data Structures

#### SessionRecord

```rust
pub struct SessionRecord {
    pub session_id: [u8; 32],           // SHA256(auth_key + btc_start)
    pub auth_key_hash: [u8; 32],        // Hash of auth key (never store key)
    pub btc_start: BtcBlock,            // Block at session start
    pub btc_end: Option<BtcBlock>,      // Block at session end
    pub branch: String,                  // branch-(height % 7 + 1)
    pub interactions: Vec<InteractionHash>,
    pub final_hash: Option<[u8; 32]>,   // Session close hash
}

pub struct BtcBlock {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
}
```

#### InteractionRecord

```rust
pub struct InteractionRecord {
    pub sequence: u64,                   // Interaction number in session
    pub timestamp: u64,
    pub prompt_hash: [u8; 32],           // SHA256(prompt_content)
    pub response_hash: [u8; 32],         // SHA256(response_content)
    pub chain_hash: [u8; 32],            // SHA256(prev + prompt + response)
    pub model: String,                   // sonnet/opus/haiku
}
```

### 4. Branch Strategy

```
BTC_HEIGHT % 7 + 1 = BRANCH_NUMBER

Height 930226 → 930226 % 7 + 1 = 2 → branch-2
Height 930227 → 930227 % 7 + 1 = 3 → branch-3
Height 930228 → 930228 % 7 + 1 = 4 → branch-4
...

7 rotating branches (branch-1 through branch-7)
Sessions on same branch share temporal proximity
```

---

## Integration Points

### 4.1 Claude API Client Integration

**File**: `gently-brain/src/claude.rs`

Current `chat()` method needs modification:

```rust
// CURRENT (no audit)
pub fn chat(&mut self, message: &str) -> Result<String> {
    self.conversation.push(Message::user(message));
    // ... API call ...
    Ok(text)
}

// REQUIRED (with audit)
pub fn chat(&mut self, message: &str, session: &mut SessionRecord) -> Result<String> {
    // 1. Validate auth key
    if !self.validate_auth(session.auth_key_hash)? {
        return Err(Error::AuthFailed("Invalid auth key"));
    }

    // 2. Hash prompt
    let prompt_hash = sha256(message.as_bytes());

    // 3. Make API call
    self.conversation.push(Message::user(message));
    let response = self.api_call()?;

    // 4. Hash response
    let response_hash = sha256(response.as_bytes());

    // 5. Chain hash
    let prev_hash = session.interactions.last()
        .map(|i| i.chain_hash)
        .unwrap_or(session.session_id);
    let chain_hash = sha256(&[prev_hash, prompt_hash, response_hash].concat());

    // 6. Record interaction
    session.interactions.push(InteractionRecord {
        sequence: session.interactions.len() as u64 + 1,
        timestamp: now(),
        prompt_hash,
        response_hash,
        chain_hash,
        model: self.model.api_name().to_string(),
    });

    // 7. Commit to branch
    self.commit_interaction(&session)?;

    Ok(response)
}
```

### 4.2 CLI Integration

**File**: `gently-cli/src/main.rs`

```rust
// Session start
fn start_claude_session() -> Result<SessionRecord> {
    let auth_key = get_auth_key()?;
    let btc = fetch_btc_block()?;
    let branch = format!("branch-{}", (btc.height % 7) + 1);

    let session_id = sha256(&[
        sha256(auth_key.as_bytes()),
        btc.hash.as_bytes()
    ].concat());

    // Create/switch to branch
    git_checkout_create(&branch)?;

    // Log to audit chain
    audit_log(&format!("session_start:{}:btc-{}",
        hex::encode(&session_id[..8]), btc.height))?;

    Ok(SessionRecord {
        session_id,
        auth_key_hash: sha256(auth_key.as_bytes()),
        btc_start: btc,
        btc_end: None,
        branch,
        interactions: vec![],
        final_hash: None,
    })
}

// Session end
fn end_claude_session(session: &mut SessionRecord) -> Result<()> {
    let btc = fetch_btc_block()?;
    session.btc_end = Some(btc.clone());

    let final_hash = sha256(&[
        session.session_id.as_slice(),
        btc.hash.as_bytes(),
        session.interactions.last()
            .map(|i| i.chain_hash.as_slice())
            .unwrap_or(&[0u8; 32])
    ].concat());

    session.final_hash = Some(final_hash);

    // Commit final state
    git_commit(&format!("session_end:{}:btc-{}",
        hex::encode(&final_hash[..8]), btc.height))?;

    // Return to main
    git_checkout("main")?;

    // Log to audit chain
    audit_log(&format!("session_end:{}:btc-{}",
        hex::encode(&final_hash[..8]), btc.height))?;

    Ok(())
}
```

### 4.3 Watchdog Integration

**File**: `gently-brain/src/watchdog.rs`

Add session-aware event types:

```rust
pub enum EventKind {
    // Existing
    Alert = 0x01,
    Anomaly = 0x02,
    // ...

    // New for sessions
    SessionStart = 0x10,
    SessionEnd = 0x11,
    PromptSubmit = 0x12,
    ResponseReceive = 0x13,
    AuthValidate = 0x14,
    BtcAnchor = 0x15,
}
```

### 4.4 GitChain Integration

**File**: `gently-brain/src/gitchain.rs`

Add session-aware commits:

```rust
impl GitChain {
    pub fn commit_interaction(
        &mut self,
        interaction: &InteractionRecord,
        session_id: &[u8; 32]
    ) -> Hash {
        let mut tree = Manifest::new();

        // Add interaction hashes to tree
        let prompt_blob = Blob::new(Kind::Hash, interaction.prompt_hash.to_vec());
        let response_blob = Blob::new(Kind::Hash, interaction.response_hash.to_vec());

        tree.add(TAG_PROMPT, self.put(prompt_blob));
        tree.add(TAG_RESPONSE, self.put(response_blob));
        tree.add(TAG_SESSION, Hash::from_bytes(session_id));

        self.commit(
            tree,
            &format!("interaction-{}", interaction.sequence),
            &hex::encode(&session_id[..8])
        )
    }
}
```

---

## Audit Log Format

### Current Format

```
HASH|BTC_HEIGHT|TIMESTAMP|COMMAND
```

### Required Format

```
HASH|BTC_HEIGHT|TIMESTAMP|EVENT_TYPE|SESSION_ID|DETAILS
```

**Event Types**:
- `session_start` - New session begun
- `session_end` - Session closed
- `prompt` - User prompt submitted
- `response` - Claude response received
- `auth_fail` - Auth validation failed
- `branch_create` - New branch created
- `branch_switch` - Switched branches

**Example**:
```
6365411d...|930226|2025-12-31T04:25:37Z|session_start|a7f3b8e4|btc:930226,branch:branch-2
7812ef23...|930226|2025-12-31T04:25:38Z|prompt|a7f3b8e4|hash:c9f5d0a6...,seq:1
8923fa34...|930226|2025-12-31T04:25:40Z|response|a7f3b8e4|hash:d0a6e1b7...,seq:1,model:sonnet
...
9034ab45...|930227|2025-12-31T05:15:22Z|session_end|a7f3b8e4|btc:930227,interactions:47
```

---

## Implementation Checklist

### Phase 1: Core Hashing (CRITICAL)

- [ ] Add `prompt_hash` field to Claude interaction
- [ ] Add `response_hash` field to Claude interaction
- [ ] Create `InteractionRecord` struct
- [ ] Create `SessionRecord` struct
- [ ] Implement chain hashing: `SHA256(prev + prompt + response)`

### Phase 2: Auth Integration (CRITICAL)

- [ ] Define auth key storage (vault)
- [ ] Implement auth key validation before prompts
- [ ] Add `auth_key_hash` to session (never store plaintext)
- [ ] Add auth failure event logging

### Phase 3: BTC Anchoring (HIGH)

- [ ] Create Rust BTC block fetcher (replace shell curl)
- [ ] Implement session start BTC anchor
- [ ] Implement session end BTC anchor
- [ ] Add BTC block to audit log entries

### Phase 4: Branch Management (HIGH)

- [ ] Integrate GitChain with sessions
- [ ] Auto-create branch on session start
- [ ] Commit interactions to session branch
- [ ] Merge/archive on session end

### Phase 5: Audit Trail (MEDIUM)

- [ ] Extend audit.log format
- [ ] Add session ID to all entries
- [ ] Add event type field
- [ ] Create audit chain verification tool

---

## Verification

### Hash Chain Verification

```bash
# Verify chain integrity
gently audit verify

# Output:
# Genesis: 39d8668c9e1c18834931c26be61912c018fcc8e17d52f36b0a00c7020fe1ab69
# Entries: 247
# Chain integrity: VALID
# BTC anchors: 23
# Sessions: 12
```

### Session Verification

```bash
# Verify specific session
gently audit session a7f3b8e4

# Output:
# Session: a7f3b8e4...
# Start BTC: 930226
# End BTC: 930227
# Interactions: 47
# Branch: branch-2
# Chain integrity: VALID
# All hashes verified: YES
```

---

## Security Considerations

1. **Auth keys** - Never stored in plaintext, only hashes
2. **Prompt/Response** - Only hashes stored in chain, content in ephemeral memory
3. **BTC dependency** - Fallback to local timestamp if API unavailable
4. **Branch isolation** - Each session on separate branch prevents collision
5. **Genesis anchor** - All chains trace back to genesis hash

---

**Document Status**: SPECIFICATION
**Implementation Status**: PARTIAL (shell scripts only)
**Priority**: CRITICAL for production deployment
