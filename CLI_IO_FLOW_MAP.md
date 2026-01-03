# GentlyOS CLI I/O Flow Map
## Complete Filesystem and Network I/O from App Start to Logoff

**Generated**: 2026-01-02
**Binary**: `/root/gentlyos/target/release/gently`

---

## Table of Contents

1. [Entry Point](#1-entry-point)
2. [Global State Initialization](#2-global-state-initialization)
3. [File System I/O Map](#3-file-system-io-map)
4. [Network I/O Map](#4-network-io-map)
5. [Claude Command Flow](#5-claude-command-flow)
6. [Complete Lifecycle Diagram](#6-complete-lifecycle-diagram)
7. [Security Audit Points](#7-security-audit-points)

---

## 1. Entry Point

### Binary Invocation

```
User Shell
    │
    ▼
/root/gentlyos/target/release/gently [COMMAND] [ARGS]
    │
    ▼
main() @ gently-cli/src/main.rs:1259
    │
    ▼
Cli::parse() ─── clap argument parsing
    │
    ▼
match cli.command { ... }
    │
    ├── Commands::Install     → cmd_install()
    ├── Commands::Init        → cmd_init()
    ├── Commands::Claude      → cmd_claude()     ◄── FOCUS
    ├── Commands::Vault       → cmd_vault()
    ├── Commands::Feed        → cmd_feed()
    ├── Commands::Search      → cmd_search()
    ├── Commands::Mcp         → cmd_mcp()
    ├── Commands::Brain       → cmd_brain()
    ├── Commands::Report      → report::run_report()
    └── ... (40+ commands)
```

### Dependencies Loaded at Startup

```rust
// main.rs:1-37 - All imports loaded at binary start
use gently_core::{GenesisKey, PatternEncoder, Lock, Key, KeyVault, ServiceConfig};
use gently_feed::{FeedStorage, ItemKind, LivingFeed};
use gently_search::{ContextRouter, Thought, ThoughtIndex};
use gently_mcp::{McpServer, McpHandler};
use gently_dance::{DanceSession, Contract};
use gently_brain::{ClaudeClient, ClaudeModel, GentlyAssistant, ...};
use gently_ipfs::{IpfsClient, IpfsOperations, PinStrategy};
// ... 16 total crates
```

---

## 2. Global State Initialization

### Lazy-Initialized Singletons

```rust
// main.rs:1296-1306 - Global state (Mutex-guarded)
static DEMO_GENESIS: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static DEMO_TOKEN: Mutex<Option<GntlyToken>> = Mutex::new(None);
static DEMO_CERTIFICATION: Mutex<Option<CertificationManager>> = Mutex::new(None);
static DEMO_PERMISSIONS: Mutex<Option<PermissionManager>> = Mutex::new(None);
static DEMO_INSTALL: Mutex<Option<GentlyInstall>> = Mutex::new(None);
static DEMO_GOS_TOKEN: Mutex<Option<GosToken>> = Mutex::new(None);
static DEMO_GOVERNANCE: Mutex<Option<GovernanceSystem>> = Mutex::new(None);
static DEMO_GENOS: Mutex<Option<GenosEconomy>> = Mutex::new(None);
static DEMO_VAULT: Mutex<Option<KeyVault>> = Mutex::new(None);
```

### Genesis Key Generation

```
get_demo_genesis() @ main.rs:1307-1315
    │
    ├── Check DEMO_GENESIS.lock()
    │       │
    │       └── if None:
    │               │
    │               ▼
    │           rand::thread_rng().fill_bytes(&mut genesis)
    │               │
    │               ▼
    │           Store 32-byte random genesis
    │
    └── Return cached genesis bytes
```

---

## 3. File System I/O Map

### Read Locations

| Path | Component | Purpose | Trigger |
|------|-----------|---------|---------|
| `~/.config/gently/feed.json` | gently-feed | Living Feed state | `gently feed show` |
| `~/.config/gently/thoughts.db` | gently-search | Thought index SQLite | `gently search` |
| `~/.local/share/gently/vault.enc` | gently-core | Encrypted API keys | `gently vault load` |
| `~/.local/share/gently/models/*.gguf` | gently-brain | LLM model files | `gently brain` |
| `~/.local/share/gently/models/*.onnx` | gently-brain | Embedding models | `gently brain embed` |
| `~/.cache/gently/ipfs/*` | gently-ipfs | IPFS content cache | `gently ipfs get` |
| `$ANTHROPIC_API_KEY` (env) | gently-brain | Claude API key | `gently claude` |

### Write Locations

| Path | Component | Purpose | Trigger |
|------|-----------|---------|---------|
| `~/.config/gently/feed.json` | gently-feed | Feed state save | `gently feed add/boost` |
| `~/.config/gently/thoughts.db` | gently-search | Thought index | `gently search add` |
| `~/.local/share/gently/vault.enc` | gently-core | Vault save | `gently vault save` |
| `~/.local/share/gently/models/*` | gently-brain | Model download | `gently brain download` |
| `~/.cache/gently/ipfs/*` | gently-ipfs | IPFS cache | `gently ipfs add` |
| `./output.svg` | gently-visual | Pattern output | `gently pattern -o` |
| `./install.json` | gently-cli | Install manifest | `gently install -o` |
| `./export.md` | gently-feed | Markdown export | `gently feed export` |

### Path Resolution Logic

```rust
// Cross-platform path resolution
dirs::config_dir()     // ~/.config (Linux), ~/Library/Application Support (macOS)
dirs::data_local_dir() // ~/.local/share (Linux), ~/Library/Application Support (macOS)
dirs::cache_dir()      // ~/.cache (Linux), ~/Library/Caches (macOS)

// Fallback chain:
// 1. XDG_CONFIG_HOME / XDG_DATA_HOME / XDG_CACHE_HOME
// 2. $HOME/.config / $HOME/.local/share / $HOME/.cache
// 3. Current directory "."
```

---

## 4. Network I/O Map

### Outbound HTTP Requests

| Endpoint | Component | Method | Purpose |
|----------|-----------|--------|---------|
| `https://api.anthropic.com/v1/messages` | gently-brain | POST | Claude API calls |
| `https://blockchain.info/latestblock` | audit.sh | GET | BTC block height |
| `https://huggingface.co/.../*.gguf` | gently-brain | GET | Model downloads |
| `https://huggingface.co/.../*.onnx` | gently-brain | GET | Embedder downloads |
| `http://localhost:5001/api/v0/*` | gently-ipfs | POST | IPFS daemon API |

### Claude API Request Structure

```
POST https://api.anthropic.com/v1/messages
Headers:
    x-api-key: $ANTHROPIC_API_KEY
    anthropic-version: 2023-06-01
    content-type: application/json

Body:
{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 4096,
    "system": "You are GentlyOS assistant...",
    "messages": [
        {"role": "user", "content": "..."},
        {"role": "assistant", "content": "..."}
    ]
}

Response:
{
    "content": [{"type": "text", "text": "..."}],
    "model": "...",
    "stop_reason": "end_turn",
    "usage": {"input_tokens": N, "output_tokens": M}
}
```

---

## 5. Claude Command Flow

### 5.1 `gently claude chat "message"`

```
USER INPUT
    │
    ▼
cmd_claude(ClaudeCommands::Chat { message, model })
    │                                    @ main.rs:4910
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     INITIALIZATION                            │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ClaudeModel::from_str(&model)                               │
│      │                                                        │
│      └── "sonnet" → Sonnet4                                  │
│          "opus"   → Opus4                                    │
│          "haiku"  → Haiku35                                  │
│                                                               │
│  GentlyAssistant::with_model(model_type)                     │
│      │                                     @ brain/claude.rs │
│      ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ ENV READ: std::env::var("ANTHROPIC_API_KEY")            │ │
│  │                                                          │ │
│  │ if Err → return Error("API key not set")                │ │
│  │ if Ok  → store in ClaudeClient.api_key                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  Set system prompt:                                          │
│  "You are the GentlyOS assistant, an AI designed to help    │
│   with security, cryptography, and knowledge management."    │
│                                                               │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     API CALL                                  │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  assistant.chat(&message)                                    │
│      │                                    @ brain/claude.rs  │
│      ▼                                                        │
│  conversation.push(Message::user(message))                   │
│      │                                                        │
│      ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ NETWORK I/O:                                             │ │
│  │                                                          │ │
│  │ ureq::post("https://api.anthropic.com/v1/messages")     │ │
│  │     .set("x-api-key", &self.api_key)                    │ │
│  │     .set("anthropic-version", "2023-06-01")             │ │
│  │     .set("content-type", "application/json")            │ │
│  │     .send_json(&request_body)                           │ │
│  │                                                          │ │
│  │ BLOCKING: Waits for API response                        │ │
│  └─────────────────────────────────────────────────────────┘ │
│      │                                                        │
│      ▼                                                        │
│  Parse response.content[0].text                              │
│      │                                                        │
│      ▼                                                        │
│  conversation.push(Message::assistant(response))             │
│                                                               │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     OUTPUT                                    │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  STDOUT:                                                     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  CLAUDE CHAT                                            │ │
│  │  ===========                                            │ │
│  │  Model: Claude Sonnet 4                                 │ │
│  │                                                          │ │
│  │  You: {message}                                         │ │
│  │                                                          │ │
│  │  Claude:                                                │ │
│  │  {response text with word wrapping}                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  NO FILE I/O (conversation not persisted)                    │
│                                                               │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
Return Ok(())
```

### 5.2 `gently claude repl`

```
USER INPUT
    │
    ▼
cmd_claude(ClaudeCommands::Repl { model, system })
    │                                    @ main.rs:4980
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     REPL INITIALIZATION                       │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ClaudeClient::new()                                         │
│      │                                                        │
│      └── ENV READ: ANTHROPIC_API_KEY                         │
│                                                               │
│  client.model(model_type)                                    │
│  client.system(system_prompt) if provided                    │
│                                                               │
│  STDOUT: "CLAUDE REPL"                                       │
│          "==========="                                       │
│          "Model: {model}"                                    │
│          "Type 'exit' to end session."                       │
│                                                               │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────┐
│                     REPL LOOP                                 │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  loop {                                                       │
│      │                                                        │
│      ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ STDIN READ:                                             │ │
│  │                                                          │ │
│  │ print!("  you> ");                                      │ │
│  │ io::stdout().flush();                                   │ │
│  │ stdin.lock().read_line(&mut input);                     │ │
│  │                                                          │ │
│  │ BLOCKING: Waits for user input                          │ │
│  └─────────────────────────────────────────────────────────┘ │
│      │                                                        │
│      ▼                                                        │
│  match input.trim() {                                        │
│      "exit"|"quit"|"q" → break                              │
│      "clear"           → client.clear(); continue           │
│      "help"            → print help; continue               │
│      _                 → send to Claude                     │
│  }                                                            │
│      │                                                        │
│      ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ NETWORK I/O:                                             │ │
│  │                                                          │ │
│  │ client.chat(input)                                      │ │
│  │     │                                                    │ │
│  │     └── POST to api.anthropic.com                       │ │
│  │         (includes full conversation history)            │ │
│  │                                                          │ │
│  │ BLOCKING: Waits for API response                        │ │
│  └─────────────────────────────────────────────────────────┘ │
│      │                                                        │
│      ▼                                                        │
│  STDOUT: "  claude>"                                         │
│          "{response text}"                                   │
│                                                               │
│  } // end loop                                               │
│                                                               │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
STDOUT: "  Goodbye!"
Return Ok(())
```

### 5.3 `gently vault` Integration with Claude

```
┌───────────────────────────────────────────────────────────────┐
│              VAULT → CLAUDE INTEGRATION                       │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  gently vault set anthropic sk-ant-xxxxx                     │
│      │                                                        │
│      ▼                                                        │
│  KeyVault::set("anthropic", key)                             │
│      │                                                        │
│      ├── Generate random 16-byte salt                        │
│      │                                                        │
│      ├── derive_key = SHA256(genesis + "anthropic" + salt)   │
│      │                                                        │
│      ├── encrypted = XOR(key_bytes, derived_key)             │
│      │                                                        │
│      └── Store VaultEntry in manifest.entries                │
│                                                               │
│  gently vault save                                           │
│      │                                                        │
│      ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ FILE WRITE:                                             │ │
│  │                                                          │ │
│  │ path = ~/.local/share/gently/vault.enc                  │ │
│  │ std::fs::create_dir_all(parent)                         │ │
│  │ std::fs::write(path, vault.export())                    │ │
│  │                                                          │ │
│  │ Content: JSON-encoded VaultManifest (encrypted keys)    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  gently vault get anthropic --export                         │
│      │                                                        │
│      ▼                                                        │
│  KeyVault::get("anthropic")                                  │
│      │                                                        │
│      ├── derive_key = SHA256(genesis + "anthropic" + salt)   │
│      │                                                        │
│      ├── decrypted = XOR(encrypted, derived_key)             │
│      │                                                        │
│      └── std::env::set_var("ANTHROPIC_API_KEY", decrypted)  │
│                                                               │
│  NOW: gently claude works with vault-stored key              │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## 6. Complete Lifecycle Diagram

### App Start → Chat → Compute → Logoff

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           USER SESSION                                  │
└─────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════╗
║                          1. APP START                                 ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  Shell Invocation:                                                    ║
║  $ gently claude repl -m sonnet                                       ║
║                                                                       ║
║  ┌─────────────────┐                                                  ║
║  │ Binary Loading  │                                                  ║
║  │                 │                                                  ║
║  │ - Load ELF      │                                                  ║
║  │ - Init runtime  │                                                  ║
║  │ - Parse args    │                                                  ║
║  └────────┬────────┘                                                  ║
║           │                                                           ║
║           ▼                                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                    ENVIRONMENT READS                            │  ║
║  │                                                                 │  ║
║  │  ANTHROPIC_API_KEY ─────────────────────────────────► Required │  ║
║  │  HOME ───────────────────────────────────────────────► Paths   │  ║
║  │  XDG_CONFIG_HOME ────────────────────────────────────► Config  │  ║
║  │  XDG_DATA_HOME ──────────────────────────────────────► Data    │  ║
║  │  XDG_CACHE_HOME ─────────────────────────────────────► Cache   │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║           │                                                           ║
║           ▼                                                           ║
║  ┌─────────────────┐                                                  ║
║  │ Global State    │                                                  ║
║  │                 │                                                  ║
║  │ - Genesis key   │◄───── Random 32 bytes if not exists             ║
║  │ - Vault init    │◄───── Empty manifest                            ║
║  │ - Token state   │◄───── devnet defaults                           ║
║  └────────┬────────┘                                                  ║
║           │                                                           ║
╚═══════════╪═══════════════════════════════════════════════════════════╝
            │
            ▼
╔═══════════════════════════════════════════════════════════════════════╗
║                          2. CHAT PHASE                                ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  REPL Loop:                                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                                                                 │  ║
║  │   you> What is GentlyOS?                                       │  ║
║  │                           ───────────────────────────┐          │  ║
║  │                                                      │          │  ║
║  │                                                      ▼          │  ║
║  │   ┌──────────────────────────────────────────────────────────┐ │  ║
║  │   │                    STDIN READ                            │ │  ║
║  │   │                                                          │ │  ║
║  │   │  stdin.lock().read_line()                               │ │  ║
║  │   │  input = "What is GentlyOS?"                            │ │  ║
║  │   └──────────────────────────────────────────────────────────┘ │  ║
║  │                           │                                     │  ║
║  │                           ▼                                     │  ║
║  │   ┌──────────────────────────────────────────────────────────┐ │  ║
║  │   │                 CONVERSATION STATE                       │ │  ║
║  │   │                                                          │ │  ║
║  │   │  messages: [                                             │ │  ║
║  │   │    {role: "user", content: "What is GentlyOS?"}         │ │  ║
║  │   │  ]                                                       │ │  ║
║  │   │                                                          │ │  ║
║  │   │  (Stored in memory, NOT persisted to disk)              │ │  ║
║  │   └──────────────────────────────────────────────────────────┘ │  ║
║  │                           │                                     │  ║
║  │                           ▼                                     │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
            │
            ▼
╔═══════════════════════════════════════════════════════════════════════╗
║                          3. COMPUTE PHASE                             ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                      NETWORK I/O                                │  ║
║  │                                                                 │  ║
║  │  ┌────────────────────────────────────────────────────────────┐│  ║
║  │  │ REQUEST                                                     ││  ║
║  │  │                                                             ││  ║
║  │  │ POST https://api.anthropic.com/v1/messages                 ││  ║
║  │  │                                                             ││  ║
║  │  │ Headers:                                                    ││  ║
║  │  │   x-api-key: sk-ant-xxxxx (from ANTHROPIC_API_KEY)        ││  ║
║  │  │   anthropic-version: 2023-06-01                            ││  ║
║  │  │   content-type: application/json                           ││  ║
║  │  │                                                             ││  ║
║  │  │ Body:                                                       ││  ║
║  │  │   {                                                         ││  ║
║  │  │     "model": "claude-sonnet-4-20250514",                   ││  ║
║  │  │     "max_tokens": 4096,                                     ││  ║
║  │  │     "system": "You are GentlyOS assistant...",             ││  ║
║  │  │     "messages": [{...}]                                    ││  ║
║  │  │   }                                                         ││  ║
║  │  └────────────────────────────────────────────────────────────┘│  ║
║  │                           │                                     │  ║
║  │                           │ BLOCKING HTTP                       │  ║
║  │                           │ (ureq::post)                        │  ║
║  │                           ▼                                     │  ║
║  │  ┌────────────────────────────────────────────────────────────┐│  ║
║  │  │ RESPONSE                                                    ││  ║
║  │  │                                                             ││  ║
║  │  │ {                                                           ││  ║
║  │  │   "content": [{"type": "text", "text": "GentlyOS is..."}],││  ║
║  │  │   "model": "claude-sonnet-4-20250514",                     ││  ║
║  │  │   "stop_reason": "end_turn",                               ││  ║
║  │  │   "usage": {"input_tokens": 50, "output_tokens": 200}      ││  ║
║  │  │ }                                                           ││  ║
║  │  └────────────────────────────────────────────────────────────┘│  ║
║  │                                                                 │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║                           │                                           ║
║                           ▼                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                      STDOUT WRITE                               │  ║
║  │                                                                 │  ║
║  │   claude>                                                       │  ║
║  │   GentlyOS is a content-addressable, token-governed            │  ║
║  │   operating system built in Rust. It combines XOR              │  ║
║  │   split-knowledge security with a three-token economy...       │  ║
║  │                                                                 │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
            │
            │  (Loop continues for more messages)
            │
            ▼
╔═══════════════════════════════════════════════════════════════════════╗
║                          4. LOGOFF PHASE                              ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║  User types: exit                                                     ║
║                           │                                           ║
║                           ▼                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                      CLEANUP                                    │  ║
║  │                                                                 │  ║
║  │  - Break from REPL loop                                        │  ║
║  │  - Print "Goodbye!"                                            │  ║
║  │  - Drop ClaudeClient (conversation lost)                       │  ║
║  │  - Drop global state Mutex guards                              │  ║
║  │                                                                 │  ║
║  │  NO FILE I/O:                                                  │  ║
║  │  - Conversation NOT saved to disk                              │  ║
║  │  - Session NOT logged to audit trail                           │  ║
║  │  - NO BTC anchoring performed                                  │  ║
║  │                                                                 │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║                           │                                           ║
║                           ▼                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │                      PROCESS EXIT                               │  ║
║  │                                                                 │  ║
║  │  return Ok(()) from main()                                     │  ║
║  │  exit code: 0                                                   │  ║
║  │                                                                 │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

---

## 7. Security Audit Points

### Missing I/O (Gaps)

| What's Missing | Impact | Priority |
|----------------|--------|----------|
| Session logging to audit.log | No audit trail for Claude interactions | CRITICAL |
| Prompt/response hashing | Cannot verify conversation integrity | CRITICAL |
| BTC block anchoring | Sessions not timestamped immutably | HIGH |
| Conversation persistence | Sessions lost on exit | MEDIUM |
| Branch creation per session | No session isolation | MEDIUM |

### Current Security Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      CURRENT SECURITY STATE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ENV VARS                                                               │
│  ─────────                                                              │
│  ANTHROPIC_API_KEY: Read from environment                              │
│                     NOT validated before use                           │
│                     NOT logged when accessed                           │
│                                                                         │
│  VAULT                                                                  │
│  ─────                                                                  │
│  Keys: XOR encrypted with derived key                                  │
│        Derived from: SHA256(genesis + service + salt)                  │
│        Storage: ~/.local/share/gently/vault.enc                        │
│        Signature: HMAC-like with genesis key                           │
│                                                                         │
│  CONVERSATION                                                           │
│  ────────────                                                           │
│  Storage: In-memory only                                               │
│  Persistence: NONE                                                     │
│  Hashing: NONE                                                         │
│  Audit: NONE                                                           │
│                                                                         │
│  NETWORK                                                                │
│  ───────                                                                │
│  TLS: Yes (HTTPS)                                                      │
│  Certificate validation: ureq default                                  │
│  Request logging: NONE                                                 │
│  Response logging: NONE                                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Required Additions for BTC-Anchored Audit

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      REQUIRED ADDITIONS                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. SESSION START                                                       │
│     - Fetch BTC block (height, hash)                                   │
│     - Create session_id = SHA256(genesis + btc_block)                  │
│     - Create/checkout branch-(height % 7 + 1)                          │
│     - Log: session_start|btc|timestamp|session_id                      │
│                                                                         │
│  2. EACH PROMPT                                                         │
│     - prompt_hash = SHA256(prompt_content)                             │
│     - Log: prompt|btc|timestamp|session_id|prompt_hash                 │
│                                                                         │
│  3. EACH RESPONSE                                                       │
│     - response_hash = SHA256(response_content)                         │
│     - chain_hash = SHA256(prev_hash + prompt_hash + response_hash)     │
│     - Commit to branch: tree{prompt_hash, response_hash, chain_hash}   │
│     - Log: response|btc|timestamp|session_id|response_hash|chain_hash  │
│                                                                         │
│  4. SESSION END                                                         │
│     - Fetch BTC block (height, hash)                                   │
│     - final_hash = SHA256(session_id + btc_block + last_chain_hash)    │
│     - Commit final state to branch                                     │
│     - Log: session_end|btc|timestamp|session_id|final_hash             │
│     - Checkout main                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Summary

### I/O Statistics

| Category | Count |
|----------|-------|
| File read locations | 7 |
| File write locations | 8 |
| Network endpoints | 5 |
| Environment variables read | 5 |
| Global singletons | 9 |

### Critical Observations

1. **No conversation persistence** - Sessions lost on exit
2. **No audit logging** - Claude interactions not recorded
3. **No prompt/response hashing** - Cannot verify integrity
4. **No BTC anchoring in Rust** - Only shell scripts have this
5. **API key in environment only** - Vault integration exists but not used by default

---

**Document Status**: COMPLETE
**Last Updated**: 2026-01-02
