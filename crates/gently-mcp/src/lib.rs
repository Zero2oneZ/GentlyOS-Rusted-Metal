//! # Gently MCP
//!
//! Model Context Protocol server for GentlyOS.
//! Provides tools for sandboxed Claude integration.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           MCP SERVER                                         │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  USER'S CLAUDE ◄───────────────────────────────────────────────────────┐   │
//! │       │                                                                 │   │
//! │       │  MCP Protocol (JSON-RPC over stdio)                            │   │
//! │       ▼                                                                 │   │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │   │
//! │  │                       TOOL REGISTRY                              │   │   │
//! │  │                                                                  │   │   │
//! │  │  living_feed_show      → View feed state                        │   │   │
//! │  │  living_feed_boost     → Boost item charge                      │   │   │
//! │  │  living_feed_add       → Add new item                           │   │   │
//! │  │  thought_add           → Add thought to index                   │   │   │
//! │  │  thought_search        → Search thought index                   │   │   │
//! │  │  dance_initiate        → Start Dance handshake                  │   │   │
//! │  │  identity_verify       → Verify identity via Dance              │   │   │
//! │  │                                                                  │   │   │
//! │  └──────────────────────────────────────────────────────────────────┘   │   │
//! │                              │                                          │   │
//! │                              ▼                                          │   │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │   │
//! │  │ gently-feed  │  │gently-search │  │ gently-dance │                  │   │
//! │  │              │  │              │  │              │                  │   │
//! │  │ Living Feed  │  │ ThoughtIndex │  │   Protocol   │                  │   │
//! │  └──────────────┘  └──────────────┘  └──────────────┘                  │   │
//! │                                                                         │   │
//! │  TOKEN-GATED ACCESS                                                     │   │
//! │  ─────────────────                                                      │   │
//! │  • Verify SPL token balance before tool execution                       │   │
//! │  • Dance Protocol for sensitive operations                              │   │
//! │  • User's API key never leaves their machine                            │   │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Sandboxing Model
//!
//! User runs their own Claude CLI with their own API key.
//! GentlyOS provides MCP tools that Claude can invoke.
//! No user credentials stored on GentlyOS side.

pub mod handler;
pub mod protocol;
pub mod server;
pub mod tools;
pub mod bbbcp_tools;

pub use handler::McpHandler;
pub use protocol::{McpRequest, McpResponse, Tool, ToolCall, ToolResult};
pub use server::McpServer;
pub use tools::{ToolRegistry, GentlyTool};
pub use bbbcp_tools::register_bbbcp_tools;

/// Result type for gently-mcp operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in gently-mcp
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Tool execution failed: {0}")]
    ExecutionError(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Dance required for this operation")]
    DanceRequired,
}
