# nvim-gentlyos

GentlyOS integration for Neovim - AI-powered code assistance with BONEBLOB optimization and token-secure communication.

## Features

- **AI Chat** - Floating window chat interface
- **Code Explanation** - Select code and get explanations
- **Refactoring** - AI-powered refactoring suggestions
- **Test Generation** - Generate unit tests for selected code
- **BONEBLOB Optimization** - Token-efficient queries via CIRCLE elimination
- **Token Security** - Credential detection, masking, and response sanitization

## Installation

### lazy.nvim

```lua
{
  "gentlyos/nvim-gentlyos",
  config = function()
    require("gentlyos").setup({
      provider = "claude", -- claude, gpt, deepseek, grok, ollama
      boneblob = {
        enabled = true,
        passes = 5,
      },
      security = {
        token_watchdog = true,
        mask_tokens = true,
        sanitize_responses = true,
      },
    })
  end,
}
```

### packer.nvim

```lua
use {
  "gentlyos/nvim-gentlyos",
  config = function()
    require("gentlyos").setup()
  end,
}
```

### vim-plug

```vim
Plug 'gentlyos/nvim-gentlyos'

" In init.vim after plug#end():
lua require('gentlyos').setup()
```

## Requirements

- Neovim 0.8+
- `gently` CLI installed and in PATH
- API key configured via `gently vault` or environment variable

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `:GentlyChat` | Open chat window |
| `:GentlyExplain` | Explain selected code |
| `:GentlyRefactor` | Suggest refactoring |
| `:GentlyTest` | Generate unit tests |
| `:GentlyBoneblob` | Toggle BONEBLOB optimization |
| `:GentlySecurity` | Show security status |

### Default Keymaps

| Key | Mode | Action |
|-----|------|--------|
| `<leader>gc` | Normal | Open chat |
| `<leader>ge` | Visual | Explain selection |
| `<leader>gr` | Visual | Refactor selection |
| `<leader>gt` | Visual | Generate tests |
| `<leader>gb` | Normal | Toggle BONEBLOB |

### Chat Window

- `i` - Focus input
- `q` / `<Esc>` - Close window
- `<C-Enter>` - Send message

## Configuration

```lua
require("gentlyos").setup({
  -- LLM provider
  provider = "claude",

  -- BONEBLOB optimization
  boneblob = {
    enabled = true,   -- Enable constraint optimization
    passes = 5,       -- CIRCLE elimination passes (70% each)
  },

  -- Security settings
  security = {
    token_watchdog = true,      -- Detect leaked credentials
    mask_tokens = true,         -- Mask tokens in logs
    sanitize_responses = true,  -- Filter injection patterns
  },

  -- MCP server
  mcp = {
    auto_start = true,    -- Start on plugin load
    timeout = 30000,      -- Request timeout (ms)
  },

  -- Custom keymaps
  keymaps = {
    chat = "<leader>gc",
    explain = "<leader>ge",
    refactor = "<leader>gr",
    test = "<leader>gt",
    toggle_boneblob = "<leader>gb",
  },
})
```

## Security

The plugin integrates with gently-security for:

- **Token Watchdog**: Detects API keys, secrets in input/output
- **Credential Masking**: Masks sensitive data in logs
- **Response Sanitization**: Filters prompt injection patterns
- **Security Log**: Tracks security events

View security status with `:GentlySecurity`

## License

MIT
