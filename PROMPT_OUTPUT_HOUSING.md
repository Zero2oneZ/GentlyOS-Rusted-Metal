# Where Are Prompts & Outputs Housed?
## The Answer: NOWHERE (In-Memory Only)

---

## The Problem

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CURRENT STATE: NO PERSISTENCE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   SYSTEM PROMPT:                                                        │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ Location: claude.rs:519 (hardcoded const)                       │  │
│   │ Storage:  Compiled into binary                                  │  │
│   │ Editable: NO - requires recompile                               │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   USER PROMPTS:                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ Location: ClaudeClient.conversation (Vec<Message>)              │  │
│   │ Storage:  RAM only                                              │  │
│   │ Persisted: NO - lost on exit                                    │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   CLAUDE RESPONSES:                                                     │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ Location: ClaudeClient.conversation (Vec<Message>)              │  │
│   │ Storage:  RAM only                                              │  │
│   │ Persisted: NO - lost on exit                                    │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   SESSION DATA:                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ Location: ClaudeSession struct (session_id, created_at)         │  │
│   │ Storage:  RAM only                                              │  │
│   │ Persisted: NO - lost on exit                                    │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Tracing The Code

### 1. System Prompt (Hardcoded)

```rust
// claude.rs:519-538
const GENTLY_SYSTEM_PROMPT: &str = r#"You are the GentlyOS Assistant..."#;

// Used at:
// claude.rs:277
GentlyAssistant::new() {
    ClaudeClient::new()?
        .system(GENTLY_SYSTEM_PROMPT);  // ← Hardcoded, not from file
}
```

**NOT CONFIGURABLE** - Baked into the binary at compile time.

### 2. User Prompts (In-Memory)

```rust
// claude.rs:15
struct ClaudeClient {
    conversation: Vec<Message>,  // ← IN MEMORY ONLY
}

// claude.rs:172
pub fn chat(&mut self, message: &str) -> Result<String> {
    self.conversation.push(Message::user(message));  // ← Stored in RAM
    // ...
}
```

**NO FILE I/O** - Never written to disk.

### 3. Claude Responses (In-Memory)

```rust
// claude.rs:201-202
// Add assistant response to history
self.conversation.push(Message::assistant(&text));  // ← Stored in RAM
```

**NO FILE I/O** - Never written to disk.

### 4. Session Data (In-Memory)

```rust
// claude.rs:541-545
pub struct ClaudeSession {
    assistant: GentlyAssistant,
    session_id: String,           // ← UUID in RAM
    created_at: DateTime<Utc>,    // ← Timestamp in RAM
}
```

**NO FILE I/O** - Never written to disk.

---

## What Files SHOULD Exist (But Don't)

```
EXPECTED (not implemented):
==========================

~/.config/gently/
├── claude/
│   ├── system_prompt.txt        ← Configurable system prompt
│   ├── sessions/
│   │   ├── session_abc123.json  ← Persisted conversations
│   │   └── session_def456.json
│   └── config.json              ← Model preferences, max_tokens
│
├── prompts/
│   ├── prompt_hashes.log        ← SHA256 of all prompts
│   └── response_hashes.log      ← SHA256 of all responses
│
└── audit/
    └── claude_audit.log         ← BTC-anchored audit trail


ACTUAL (current state):
======================

NOTHING. No files created. All in RAM.
```

---

## The Data Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CURRENT LIFECYCLE                                │
└─────────────────────────────────────────────────────────────────────────┘

    User types: "Hello Claude"
           │
           ▼
    ┌───────────────────────────────────────────────────────────────┐
    │   IN MEMORY: conversation.push(Message::user("Hello"))       │
    │   DISK: nothing                                               │
    └───────────────────────────────────────────────────────────────┘
           │
           ▼
    POST to api.anthropic.com
           │
           ▼
    ┌───────────────────────────────────────────────────────────────┐
    │   IN MEMORY: conversation.push(Message::assistant(response)) │
    │   DISK: nothing                                               │
    └───────────────────────────────────────────────────────────────┘
           │
           ▼
    User types: "exit"
           │
           ▼
    ┌───────────────────────────────────────────────────────────────┐
    │   PROCESS EXITS                                               │
    │                                                               │
    │   ██████████████████████████████████████████████████████████  │
    │   ██  ALL DATA DESTROYED - CONVERSATION GONE FOREVER      ██  │
    │   ██████████████████████████████████████████████████████████  │
    └───────────────────────────────────────────────────────────────┘
```

---

## What Other Modules DO Have Persistence

These modules HAVE file I/O, but Claude doesn't use them:

| Module | Storage | File |
|--------|---------|------|
| **gently-feed** | JSON | `~/.config/gently/feed.json` |
| **gently-search** | JSON | `~/.config/gently/thoughts.db` |
| **gently-core vault** | Encrypted | `~/.local/share/gently/vault.enc` |
| **gently-brain tensorchain** | JSON | Custom path |
| **gently-brain download** | Binary | `~/.local/share/gently/models/` |
| **gently-brain claude** | **NONE** | **NO FILE** |

---

## What SHOULD Be Implemented

### 1. Configurable System Prompt

```rust
// CURRENT (hardcoded):
const GENTLY_SYSTEM_PROMPT: &str = r#"..."#;

// SHOULD BE (file-based):
fn load_system_prompt() -> String {
    let path = dirs::config_dir()
        .join("gently/claude/system_prompt.txt");

    if path.exists() {
        std::fs::read_to_string(&path).unwrap_or(DEFAULT_PROMPT.into())
    } else {
        DEFAULT_PROMPT.into()
    }
}
```

### 2. Session Persistence

```rust
// CURRENT:
pub struct ClaudeSession {
    conversation: Vec<Message>,  // RAM only
}

// SHOULD BE:
pub struct ClaudeSession {
    session_id: String,
    conversation: Vec<Message>,
    file_path: PathBuf,  // ← Add this
}

impl ClaudeSession {
    pub fn save(&self) -> Result<()> {
        let path = dirs::config_dir()
            .join(format!("gently/claude/sessions/{}.json", self.session_id));
        std::fs::write(&path, serde_json::to_string(&self.conversation)?)?;
        Ok(())
    }

    pub fn load(session_id: &str) -> Result<Self> {
        let path = dirs::config_dir()
            .join(format!("gently/claude/sessions/{}.json", session_id));
        let data = std::fs::read_to_string(&path)?;
        let conversation = serde_json::from_str(&data)?;
        Ok(Self { session_id: session_id.into(), conversation, file_path: path })
    }
}
```

### 3. Prompt/Response Hashing

```rust
// Add to chat() function:
pub fn chat(&mut self, message: &str) -> Result<String> {
    // Hash prompt BEFORE sending
    let prompt_hash = sha256(message.as_bytes());
    log_hash("prompt", &prompt_hash);

    self.conversation.push(Message::user(message));
    let response = self.api_call()?;

    // Hash response AFTER receiving
    let response_hash = sha256(response.as_bytes());
    log_hash("response", &response_hash);

    self.conversation.push(Message::assistant(&response));
    Ok(response)
}

fn log_hash(event_type: &str, hash: &[u8; 32]) {
    let path = dirs::config_dir().join("gently/audit/claude_hashes.log");
    let entry = format!("{}|{}|{}\n",
        chrono::Utc::now().to_rfc3339(),
        event_type,
        hex::encode(hash)
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(entry.as_bytes()))
        .ok();
}
```

### 4. BTC-Anchored Audit

```rust
// Add BTC block to session start/end:
pub fn start_session() -> Result<ClaudeSession> {
    let btc = fetch_btc_block()?;  // Get current BTC height/hash
    let session_id = sha256(&format!("{}:{}", btc.hash, Uuid::new_v4()));

    audit_log(&format!("session_start|{}|btc:{}",
        hex::encode(&session_id[..8]), btc.height));

    Ok(ClaudeSession::new(session_id))
}
```

---

## Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CURRENT STATE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   SYSTEM PROMPT:     Hardcoded const (claude.rs:519)                   │
│   USER PROMPTS:      Vec<Message> in RAM → LOST ON EXIT                │
│   CLAUDE RESPONSES:  Vec<Message> in RAM → LOST ON EXIT                │
│   SESSION DATA:      struct in RAM → LOST ON EXIT                      │
│   HASH LOGGING:      NOT IMPLEMENTED                                   │
│   BTC ANCHORING:     NOT IMPLEMENTED                                   │
│   FILE PERSISTENCE:  NOT IMPLEMENTED                                   │
│                                                                         │
│   Files written by Claude module: ZERO                                  │
│   Files read by Claude module: ZERO (except env var)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Action Items

- [ ] Create `~/.config/gently/claude/` directory structure
- [ ] Implement `load_system_prompt()` from file
- [ ] Add `session.save()` / `session.load()`
- [ ] Hash all prompts with SHA256 before sending
- [ ] Hash all responses with SHA256 after receiving
- [ ] Log hashes to audit file
- [ ] Add BTC block anchoring to session start/end
- [ ] Integrate with existing audit.sh mechanism

---

**Report Version**: 1.0.0
**Generated**: 2026-01-02
