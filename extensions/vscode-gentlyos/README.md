# GentlyOS VS Code Extension

AI-powered code assistance with BONEBLOB optimization and token-secure communication.

## Features

- **AI Chat Panel** - Contextual code assistance with conversation history
- **Code Explanation** - Select code and get detailed explanations
- **Refactoring Suggestions** - AI-powered code improvement recommendations
- **Test Generation** - Automatic unit test creation
- **BONEBLOB Optimization** - 70% token reduction per CIRCLE pass
- **Token Security** - Credential detection, masking, and response sanitization

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Press `Ctrl+P` / `Cmd+P`
3. Type `ext install gentlyos.gentlyos`

### From VSIX

```bash
code --install-extension gentlyos-1.0.0.vsix
```

## Requirements

- **gently CLI** - Must be installed and in PATH
- **API Key** - Configure via `gently vault` or extension settings

Install gently:
```bash
curl -fsSL https://gentlyos.com/install.sh | bash
gently setup
```

## Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| GentlyOS: Open Chat | `Ctrl+Shift+G` | Open chat panel |
| GentlyOS: Explain Code | `Ctrl+Shift+E` | Explain selected code |
| GentlyOS: Suggest Refactoring | `Ctrl+Shift+R` | Refactor selected code |
| GentlyOS: Generate Tests | `Ctrl+Shift+T` | Generate unit tests |
| GentlyOS: Toggle BONEBLOB | `Ctrl+Shift+B` | Toggle optimization |
| GentlyOS: Show Living Feed | - | Show feed items |
| GentlyOS: Search Knowledge | - | Search Alexandria graph |
| GentlyOS: Security Status | - | View security events |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `gentlyos.provider` | `claude` | LLM provider |
| `gentlyos.boneblob.enabled` | `true` | Enable BONEBLOB optimization |
| `gentlyos.boneblob.passes` | `5` | CIRCLE elimination passes |
| `gentlyos.security.tokenWatchdog` | `true` | Detect leaked credentials |
| `gentlyos.security.sanitizeResponses` | `true` | Filter injection patterns |
| `gentlyos.security.maskTokensInLogs` | `true` | Mask tokens in output |
| `gentlyos.tokenLimits.maxRequest` | `4096` | Max tokens per request |
| `gentlyos.tokenLimits.maxResponse` | `2048` | Max tokens in response |
| `gentlyos.mcp.autoStart` | `true` | Auto-start MCP server |

## Security

The extension integrates with GentlyOS security infrastructure:

### Token Watchdog
Detects credentials in input/output:
- Anthropic, OpenAI, GitHub, AWS API keys
- Private keys and secrets
- JWT tokens

### Response Sanitization
Filters LLM responses for:
- Prompt injection attempts
- Credential leaks
- Suspicious patterns

### BONEBLOB Optimization
Reduces token usage via CIRCLE elimination:
- 5 passes x 70% reduction = 99.76% search space eliminated
- Bones: Immutable constraints
- Circles: What NOT to include
- Pins: Convergence solutions

## Providers

| Provider | Status | API Key Env |
|----------|--------|-------------|
| Claude | Full | `ANTHROPIC_API_KEY` |
| GPT | Supported | `OPENAI_API_KEY` |
| DeepSeek | Supported | `DEEPSEEK_API_KEY` |
| Grok | Supported | `XAI_API_KEY` |
| Ollama | Local | - |
| LM Studio | Local | - |
| HuggingFace | Supported | `HF_TOKEN` |

## Development

```bash
# Clone
git clone https://github.com/gentlyos/gentlyos
cd gentlyos/extensions/vscode-gentlyos

# Install dependencies
npm install

# Compile
npm run compile

# Watch mode
npm run watch

# Package
npm run package
```

## Architecture

```
vscode-gentlyos/
├── src/
│   ├── extension.ts      # Main entry, commands
│   ├── mcp/
│   │   └── client.ts     # MCP client with security
│   ├── views/
│   │   └── chatView.ts   # Chat webview
│   └── utils/
│       └── security.ts   # Token detection, masking
├── media/icons/
└── webviews/
```

## License

MIT
