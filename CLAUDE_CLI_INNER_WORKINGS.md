# GentlyOS Claude CLI - Inner Workings Report
## What Would Be cli.js (But It's Rust)

**Date**: 2026-01-02
**Language**: Rust (not JavaScript)
**Total Lines**: 587 (claude.rs) + 206 (CLI commands)

---

## Quick Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    GentlyOS HAS NO cli.js                               │
│                                                                         │
│  Instead, it has:                                                       │
│    • gently-brain/src/claude.rs  →  The Claude API client (587 lines)  │
│    • gently-cli/src/main.rs      →  CLI commands (lines 4906-5116)     │
│                                                                         │
│  100% Rust, 0% JavaScript                                               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. What Is The Claude CLI?

The GentlyOS Claude CLI is a **product-level** AI integration for customers. It is NOT:
- Anthropic's Claude Code (the development assistant)
- A JavaScript application
- A web interface

**What it IS**:
- A Rust-based Claude API client
- Part of the `gently` binary
- 4 commands: `chat`, `ask`, `repl`, `status`

---

## 2. File Structure (If It Were cli.js)

```
IF THIS WERE JAVASCRIPT:
========================

cli.js
├── class ClaudeClient
│   ├── constructor(apiKey)
│   ├── chat(message) → Promise<string>
│   ├── ask(question) → Promise<string>
│   └── clear()
│
├── class GentlyAssistant extends ClaudeClient
│   ├── constructor() → sets system prompt
│   ├── chatWithTools(message) → Promise<{text, toolUses}>
│   └── submitToolResults(results) → Promise<response>
│
├── class ClaudeSession
│   ├── sessionId: string
│   ├── history: Message[]
│   └── createdAt: Date
│
└── Commands
    ├── claude chat <message>
    ├── claude ask <question>
    ├── claude repl
    └── claude status


WHAT ACTUALLY EXISTS (RUST):
============================

gently-brain/src/claude.rs
├── struct ClaudeClient
│   ├── api_key: String
│   ├── model: ClaudeModel
│   ├── system_prompt: Option<String>
│   ├── conversation: Vec<Message>
│   └── max_tokens: usize
│
├── struct GentlyAssistant
│   ├── client: ClaudeClient
│   ├── tools_enabled: bool
│   └── tool_definitions: Vec<serde_json::Value>
│
├── struct ClaudeSession
│   ├── assistant: GentlyAssistant
│   ├── session_id: String
│   └── created_at: DateTime<Utc>
│
└── gently-cli/src/main.rs (lines 4906-5116)
    ├── fn cmd_claude(ClaudeCommands)
    ├── ClaudeCommands::Chat
    ├── ClaudeCommands::Ask
    ├── ClaudeCommands::Repl
    └── ClaudeCommands::Status
```

---

## 3. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER COMMAND                                   │
│                                                                         │
│   $ gently claude chat "Hello"                                          │
│   $ gently claude ask "What is GentlyOS?"                               │
│   $ gently claude repl                                                  │
│   $ gently claude status                                                │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       COMMAND PARSER                                    │
│                                                                         │
│   main.rs:1259 → Cli::parse()                                          │
│                     │                                                   │
│                     ▼                                                   │
│   match cli.command {                                                   │
│       Commands::Claude(cmd) → cmd_claude(cmd)                          │
│   }                                                                     │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     CLAUDE COMMAND HANDLER                              │
│                         main.rs:4910                                    │
│                                                                         │
│   fn cmd_claude(command: ClaudeCommands) -> Result<()> {               │
│       match command {                                                   │
│           Chat { message, model } => { ... }                           │
│           Ask { question, model } => { ... }                           │
│           Repl { model, system } => { ... }                            │
│           Status => { ... }                                            │
│       }                                                                 │
│   }                                                                     │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     CLIENT INITIALIZATION                               │
│                       claude.rs:113-128                                 │
│                                                                         │
│   impl ClaudeClient {                                                   │
│       pub fn new() -> Result<Self> {                                   │
│           ┌───────────────────────────────────────────────────────┐    │
│           │ ENV READ:                                             │    │
│           │   let api_key = env::var("ANTHROPIC_API_KEY")?;      │    │
│           │                                                       │    │
│           │ If missing → Error("ANTHROPIC_API_KEY not set")      │    │
│           └───────────────────────────────────────────────────────┘    │
│                                                                         │
│           Ok(Self {                                                     │
│               api_key,                                                  │
│               model: ClaudeModel::Sonnet,  ← default                   │
│               system_prompt: None,                                      │
│               conversation: Vec::new(),    ← empty history             │
│               max_tokens: 4096,                                         │
│           })                                                            │
│       }                                                                 │
│   }                                                                     │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     MODEL SELECTION                                     │
│                       claude.rs:26-50                                   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  User Input    │  ClaudeModel Enum   │  API Model ID            │  │
│   ├─────────────────────────────────────────────────────────────────┤  │
│   │  "sonnet"      │  ClaudeModel::Sonnet │ claude-sonnet-4-20250514│  │
│   │  "opus"        │  ClaudeModel::Opus   │ claude-opus-4-0-20250514│  │
│   │  "haiku"       │  ClaudeModel::Haiku  │ claude-3-5-haiku-2024.. │  │
│   │  (default)     │  ClaudeModel::Sonnet │ claude-sonnet-4-20250514│  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     API REQUEST                                         │
│                       claude.rs:169-218                                 │
│                                                                         │
│   pub fn chat(&mut self, message: &str) -> Result<String> {            │
│                                                                         │
│       // 1. Add user message to conversation                           │
│       self.conversation.push(Message::user(message));                  │
│                                                                         │
│       // 2. Build request body                                         │
│       let request = ApiRequest {                                       │
│           model: self.model.api_name(),     // "claude-sonnet-4-..."   │
│           max_tokens: self.max_tokens,      // 4096                    │
│           system: self.system_prompt,       // GentlyOS prompt         │
│           messages: self.conversation,      // full history            │
│       };                                                                │
│                                                                         │
│       // 3. Make HTTP request                                          │
│       ┌───────────────────────────────────────────────────────────┐    │
│       │ NETWORK I/O:                                              │    │
│       │                                                           │    │
│       │ ureq::post("https://api.anthropic.com/v1/messages")      │    │
│       │     .set("x-api-key", &self.api_key)                     │    │
│       │     .set("anthropic-version", "2023-06-01")              │    │
│       │     .set("content-type", "application/json")             │    │
│       │     .send_json(&request)                                 │    │
│       │                                                           │    │
│       │ BLOCKING CALL - waits for response                       │    │
│       └───────────────────────────────────────────────────────────┘    │
│                                                                         │
│       // 4. Parse response                                             │
│       let text = response.content[0].text;                             │
│                                                                         │
│       // 5. Add to conversation history                                │
│       self.conversation.push(Message::assistant(&text));              │
│                                                                         │
│       Ok(text)                                                          │
│   }                                                                     │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     OUTPUT TO USER                                      │
│                                                                         │
│   STDOUT:                                                               │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                                                                 │  │
│   │   CLAUDE CHAT                                                   │  │
│   │   ===========                                                   │  │
│   │   Model: Claude Sonnet 4                                        │  │
│   │                                                                 │  │
│   │   You: Hello                                                    │  │
│   │                                                                 │  │
│   │   Claude:                                                       │  │
│   │   Hello! How can I help you today?                              │  │
│   │                                                                 │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. The Four Commands Explained

### 4.1 `gently claude chat "message"`

```
PURPOSE:  Conversational chat WITH history
HISTORY:  YES - remembers previous messages
STATE:    In-memory only (lost on exit)

FLOW:
    User message
        │
        ▼
    GentlyAssistant::with_model(model)
        │
        └── Sets system prompt:
            "You are the GentlyOS Assistant..."
        │
        ▼
    assistant.chat(&message)
        │
        ├── Add to conversation: [{role: "user", content: message}]
        ├── POST to api.anthropic.com
        └── Add to conversation: [{role: "assistant", content: response}]
        │
        ▼
    Print response to stdout
```

### 4.2 `gently claude ask "question"`

```
PURPOSE:  One-shot question WITHOUT history
HISTORY:  NO - stateless
STATE:    None

FLOW:
    User question
        │
        ▼
    ClaudeClient::new()
        │
        ▼
    client.ask(&question)
        │
        ├── Create temp messages: [{role: "user", content: question}]
        ├── POST to api.anthropic.com
        └── Return response (NOT stored)
        │
        ▼
    Print response to stdout
```

### 4.3 `gently claude repl`

```
PURPOSE:  Interactive session
HISTORY:  YES - accumulates during session
STATE:    In-memory (lost on exit)

FLOW:
    ┌─────────────────────────────────────────────────────────────┐
    │                      REPL LOOP                              │
    │                                                             │
    │   loop {                                                    │
    │       │                                                     │
    │       ▼                                                     │
    │   print!("  you> ");                                       │
    │   stdin.read_line(&mut input);                             │
    │       │                                                     │
    │       ▼                                                     │
    │   match input {                                             │
    │       "exit"|"quit"|"q" → break                            │
    │       "clear"           → client.clear()                   │
    │       "help"            → print help                       │
    │       _                 → client.chat(input)               │
    │   }                                                         │
    │       │                                                     │
    │       ▼                                                     │
    │   print!("  claude>");                                     │
    │   println!("{}", response);                                │
    │   }                                                         │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘

COMMANDS:
    exit/quit/q  - End session
    clear        - Reset conversation
    help         - Show commands
```

### 4.4 `gently claude status`

```
PURPOSE:  Check configuration and connection
HISTORY:  N/A
STATE:    N/A

FLOW:
    Check ANTHROPIC_API_KEY
        │
        ├── If set: Display masked key (sk-ant-12...xyzz)
        └── If not: Show setup instructions
        │
        ▼
    List available models:
        • sonnet - Claude Sonnet 4 (balanced)
        • opus   - Claude Opus 4 (most capable)
        • haiku  - Claude 3.5 Haiku (fastest)
        │
        ▼
    Test connection:
        client.ask("Say 'OK' if you can hear me.")
        │
        ├── Success: "Connection: OK"
        └── Failure: "Connection: FAILED (reason)"
```

---

## 5. Key Data Structures

### Message (What gets sent to Claude)

```rust
struct Message {
    role: String,      // "user" or "assistant"
    content: String,   // The actual text
}

// JavaScript equivalent:
// { role: "user", content: "Hello" }
```

### ApiRequest (HTTP body)

```rust
struct ApiRequest {
    model: String,           // "claude-sonnet-4-20250514"
    max_tokens: usize,       // 4096
    system: Option<String>,  // "You are GentlyOS..."
    messages: Vec<Message>,  // Conversation history
}

// JavaScript equivalent:
// {
//     model: "claude-sonnet-4-20250514",
//     max_tokens: 4096,
//     system: "You are GentlyOS...",
//     messages: [
//         { role: "user", content: "Hello" },
//         { role: "assistant", content: "Hi!" }
//     ]
// }
```

### ApiResponse (What Claude returns)

```rust
struct ApiResponse {
    content: Vec<ContentBlock>,  // [{type: "text", text: "..."}]
    usage: Option<Usage>,        // {input_tokens: 50, output_tokens: 200}
}

struct ContentBlock {
    content_type: String,  // "text" or "tool_use"
    text: Option<String>,  // The response text
}
```

---

## 6. System Prompt (GentlyOS Identity)

```
const GENTLY_SYSTEM_PROMPT = r#"
You are the GentlyOS Assistant, an AI integrated into the GentlyOS
security operating system.

GentlyOS is a cryptographic security layer with these core components:
- Dance Protocol: Visual-audio authentication between devices
  using XOR key splitting
- BTC/SPL Bridge: Bitcoin block events trigger Solana token swaps
  for access control
- Cipher-Mesh: Cryptanalysis toolkit (dcode.fr style) for cipher
  identification and cracking
- Sploit Framework: Metasploit-style exploitation tools
  (for authorized testing only)
- Brain: Local AI with embeddings that grows smarter with use
- Network: Packet capture, MITM proxy, security analysis

Key CLI commands:
- gently dance   - Start visual-audio authentication
- gently cipher  - Cipher identification and cryptanalysis
- gently crack   - Password cracking (dictionary, bruteforce, rainbow)
- gently sploit  - Exploitation framework
- gently network - Packet capture and MITM proxy
- gently brain   - Local AI inference

Be helpful, concise, and security-focused. When discussing exploits
or attacks, always emphasize authorized use only.
"#;
```

---

## 7. Tool Use (Advanced Feature)

The `GentlyAssistant` supports Claude's tool use:

```rust
struct ToolUseResponse {
    id: String,                    // "toolu_01abc..."
    name: String,                  // "gently_search"
    input: serde_json::Value,      // {"query": "..."}
}

struct ToolResultInput {
    tool_use_id: String,           // "toolu_01abc..."
    content: String,               // Result of tool execution
    is_error: bool,                // Did the tool fail?
}
```

**Flow with tools**:
```
1. User asks: "Search for XOR encryption"
2. Claude returns: tool_use { name: "gently_search", input: {...} }
3. System executes: gently-search crate
4. System submits: tool_result { content: "Found 5 results..." }
5. Claude responds: "I found 5 results about XOR encryption..."
```

---

## 8. What's Missing (Security Gaps)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     WHAT'S NOT IMPLEMENTED                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ❌ NO session persistence                                              │
│     → Conversations lost on exit                                        │
│     → No way to resume previous chat                                    │
│                                                                         │
│  ❌ NO prompt/response hashing                                          │
│     → Cannot verify conversation integrity                              │
│     → No audit trail of what was said                                   │
│                                                                         │
│  ❌ NO BTC block anchoring                                              │
│     → Sessions not timestamped immutably                                │
│     → Cannot prove when conversation happened                           │
│                                                                         │
│  ❌ NO auth key validation                                              │
│     → Anyone with API key can chat                                      │
│     → No user identity verification                                     │
│                                                                         │
│  ❌ NO branch creation                                                  │
│     → Conversations not isolated                                        │
│     → No session-based branching                                        │
│                                                                         │
│  ❌ NO audit.log integration                                            │
│     → Claude interactions not recorded                                  │
│     → No integration with BTC audit chain                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. JavaScript Equivalent (If cli.js Existed)

If GentlyOS were written in JavaScript, `cli.js` would look like:

```javascript
// cli.js - What it would look like in JavaScript

const fetch = require('node-fetch');

class ClaudeClient {
    constructor() {
        this.apiKey = process.env.ANTHROPIC_API_KEY;
        if (!this.apiKey) {
            throw new Error('ANTHROPIC_API_KEY not set');
        }
        this.model = 'claude-sonnet-4-20250514';
        this.systemPrompt = null;
        this.conversation = [];
        this.maxTokens = 4096;
    }

    async chat(message) {
        // Add user message
        this.conversation.push({ role: 'user', content: message });

        // Make API request
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'x-api-key': this.apiKey,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
            },
            body: JSON.stringify({
                model: this.model,
                max_tokens: this.maxTokens,
                system: this.systemPrompt,
                messages: this.conversation,
            }),
        });

        const data = await response.json();
        const text = data.content[0].text;

        // Add assistant response
        this.conversation.push({ role: 'assistant', content: text });

        return text;
    }

    async ask(question) {
        // One-shot, no history
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'x-api-key': this.apiKey,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
            },
            body: JSON.stringify({
                model: this.model,
                max_tokens: this.maxTokens,
                system: this.systemPrompt,
                messages: [{ role: 'user', content: question }],
            }),
        });

        const data = await response.json();
        return data.content[0].text;
    }

    clear() {
        this.conversation = [];
    }
}

// Usage:
// const client = new ClaudeClient();
// const response = await client.chat("Hello");
```

But GentlyOS uses **Rust** instead for:
- Memory safety
- Performance
- Single binary distribution
- Integration with crypto crates

---

## 10. Quick Reference

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         QUICK REFERENCE                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  FILES:                                                                 │
│    gently-brain/src/claude.rs     →  API client (587 lines)            │
│    gently-cli/src/main.rs:4906    →  CLI commands (206 lines)          │
│                                                                         │
│  COMMANDS:                                                              │
│    gently claude chat "msg"       →  Conversational (has history)      │
│    gently claude ask "q"          →  One-shot (no history)             │
│    gently claude repl             →  Interactive session               │
│    gently claude status           →  Check connection                  │
│                                                                         │
│  MODELS:                                                                │
│    -m sonnet                      →  Claude Sonnet 4 (default)         │
│    -m opus                        →  Claude Opus 4                     │
│    -m haiku                       →  Claude 3.5 Haiku                  │
│                                                                         │
│  ENVIRONMENT:                                                           │
│    ANTHROPIC_API_KEY              →  Required for all commands         │
│                                                                         │
│  DATA STORAGE:                                                          │
│    Conversations: In-memory only (not persisted)                       │
│    Sessions: Not tracked                                                │
│    Audit: Not logged                                                    │
│                                                                         │
│  HTTP:                                                                  │
│    Endpoint: https://api.anthropic.com/v1/messages                     │
│    Library: ureq (blocking)                                            │
│    Headers: x-api-key, anthropic-version, content-type                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

**Report Version**: 1.0.0
**Generated**: 2026-01-02
