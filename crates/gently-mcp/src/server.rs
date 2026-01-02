//! MCP Server
//!
//! Handles stdio communication for the MCP protocol.

use crate::handler::McpHandler;
use crate::protocol::McpRequest;
use crate::tools::ToolContext;
use crate::Result;
use std::io::{BufRead, BufReader, Write};

/// MCP Server over stdio
pub struct McpServer {
    handler: McpHandler,
}

impl McpServer {
    /// Create a new server
    pub fn new() -> Self {
        Self {
            handler: McpHandler::new(),
        }
    }

    /// Create server with loaded context
    pub fn with_context(context: ToolContext) -> Self {
        Self {
            handler: McpHandler::with_context(context),
        }
    }

    /// Run the server (blocking, stdio)
    pub fn run(&self) -> Result<()> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = stdout.lock();

        loop {
            let mut line = String::new();

            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<McpRequest>(line) {
                        Ok(request) => {
                            let response = self.handler.handle(&request);
                            let response_json = serde_json::to_string(&response)?;
                            writeln!(writer, "{}", response_json)?;
                            writer.flush()?;
                        }
                        Err(e) => {
                            eprintln!("Failed to parse request: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }

        // Save context on exit
        self.handler.save()?;

        Ok(())
    }

    /// Handle a single request (for testing)
    pub fn handle_request(&self, request: &McpRequest) -> crate::protocol::McpResponse {
        self.handler.handle(request)
    }

    /// Get the handler
    pub fn handler(&self) -> &McpHandler {
        &self.handler
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for MCP server
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Enable debug logging
    pub debug: bool,

    /// Auto-save interval (seconds, 0 = disabled)
    pub auto_save_interval: u64,

    /// Maximum request size (bytes)
    pub max_request_size: usize,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            debug: false,
            auto_save_interval: 60,
            max_request_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::McpRequest;
    use serde_json::json;

    #[test]
    fn test_server_creation() {
        let server = McpServer::new();
        assert!(server.handler().registry().definitions().len() > 0);
    }

    #[test]
    fn test_handle_request() {
        let server = McpServer::new();
        let request = McpRequest::new("initialize").with_id(1);

        let response = server.handle_request(&request);
        assert!(response.result.is_some());
    }

    #[test]
    fn test_tool_call() {
        let server = McpServer::new();

        // Add an item
        let add_request = McpRequest::new("tools/call").with_id(1).with_params(json!({
            "name": "living_feed_add",
            "arguments": {
                "name": "Test Project",
                "kind": "project"
            }
        }));

        let response = server.handle_request(&add_request);
        assert!(response.result.is_some());

        // Show the feed
        let show_request = McpRequest::new("tools/call").with_id(2).with_params(json!({
            "name": "living_feed_show",
            "arguments": {}
        }));

        let response = server.handle_request(&show_request);
        assert!(response.result.is_some());
    }
}
