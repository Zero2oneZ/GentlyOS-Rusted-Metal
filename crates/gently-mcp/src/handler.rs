//! MCP Request Handler
//!
//! Handles incoming MCP requests and routes them to appropriate tools.

use crate::protocol::{
    error_codes, McpRequest, McpResponse, ServerCapabilities, ServerInfo, ToolCall,
};
use crate::tools::{ToolContext, ToolRegistry};
use crate::{Error, Result};
use serde_json::{json, Value};

/// Handler for MCP requests
pub struct McpHandler {
    registry: ToolRegistry,
    context: ToolContext,
    server_info: ServerInfo,
    capabilities: ServerCapabilities,
}

impl McpHandler {
    /// Create a new handler
    pub fn new() -> Self {
        Self {
            registry: ToolRegistry::new(),
            context: ToolContext::new(),
            server_info: ServerInfo::default(),
            capabilities: ServerCapabilities::default(),
        }
    }

    /// Create handler with loaded context
    pub fn with_context(context: ToolContext) -> Self {
        Self {
            registry: ToolRegistry::new(),
            context,
            server_info: ServerInfo::default(),
            capabilities: ServerCapabilities::default(),
        }
    }

    /// Handle an MCP request
    pub fn handle(&self, request: &McpRequest) -> McpResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request),
            "notifications/initialized" => {
                // Notification, no response needed
                McpResponse::success(request.id.clone(), json!({}))
            }
            _ => McpResponse::error(
                request.id.clone(),
                error_codes::METHOD_NOT_FOUND,
                format!("Method not found: {}", request.method),
            ),
        }
    }

    /// Handle initialize request
    fn handle_initialize(&self, request: &McpRequest) -> McpResponse {
        McpResponse::success(
            request.id.clone(),
            json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": self.server_info,
                "capabilities": self.capabilities
            }),
        )
    }

    /// Handle tools/list request
    fn handle_tools_list(&self, request: &McpRequest) -> McpResponse {
        let tools: Vec<Value> = self
            .registry
            .definitions()
            .into_iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema
                })
            })
            .collect();

        McpResponse::success(request.id.clone(), json!({ "tools": tools }))
    }

    /// Handle tools/call request
    fn handle_tools_call(&self, request: &McpRequest) -> McpResponse {
        let params = match &request.params {
            Some(p) => p,
            None => {
                return McpResponse::error(
                    request.id.clone(),
                    error_codes::INVALID_PARAMS,
                    "Missing params",
                )
            }
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => {
                return McpResponse::error(
                    request.id.clone(),
                    error_codes::INVALID_PARAMS,
                    "Missing tool name",
                )
            }
        };

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        let call = ToolCall {
            name: tool_name.to_string(),
            arguments,
        };

        match self.registry.execute(&call, &self.context) {
            Ok(result) => McpResponse::success(
                request.id.clone(),
                json!({
                    "content": result.content,
                    "isError": result.is_error
                }),
            ),
            Err(Error::ToolNotFound(name)) => McpResponse::error(
                request.id.clone(),
                error_codes::METHOD_NOT_FOUND,
                format!("Tool not found: {}", name),
            ),
            Err(Error::DanceRequired) => McpResponse::error(
                request.id.clone(),
                -32001, // Custom error code
                "Dance verification required for this operation",
            ),
            Err(e) => McpResponse::error(
                request.id.clone(),
                error_codes::INTERNAL_ERROR,
                format!("Tool execution failed: {}", e),
            ),
        }
    }

    /// Save context to disk
    pub fn save(&self) -> Result<()> {
        self.context.save()
    }

    /// Get the tool registry
    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// Get the context
    pub fn context(&self) -> &ToolContext {
        &self.context
    }
}

impl Default for McpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let handler = McpHandler::new();
        let request = McpRequest::new("initialize").with_id(1);

        let response = handler.handle(&request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_tools_list() {
        let handler = McpHandler::new();
        let request = McpRequest::new("tools/list").with_id(1);

        let response = handler.handle(&request);
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert!(!tools.is_empty());
    }

    #[test]
    fn test_tools_call() {
        let handler = McpHandler::new();
        let request = McpRequest::new("tools/call")
            .with_id(1)
            .with_params(json!({
                "name": "living_feed_show",
                "arguments": {}
            }));

        let response = handler.handle(&request);
        assert!(response.result.is_some());
    }

    #[test]
    fn test_unknown_method() {
        let handler = McpHandler::new();
        let request = McpRequest::new("unknown/method").with_id(1);

        let response = handler.handle(&request);
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, error_codes::METHOD_NOT_FOUND);
    }
}
