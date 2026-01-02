//! MCP Protocol types
//!
//! Implements the Model Context Protocol message types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP Request (JSON-RPC 2.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl McpRequest {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(1.into())),
            method: method.into(),
            params: None,
        }
    }

    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }

    pub fn with_id(mut self, id: impl Into<Value>) -> Self {
        self.id = Some(id.into());
        self
    }
}

/// MCP Response (JSON-RPC 2.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

impl McpResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(McpError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// MCP Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Standard error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

impl Tool {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    pub fn with_schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }
}

/// Tool call request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    #[serde(rename = "type")]
    pub result_type: String,
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl ToolResult {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            result_type: "tool_result".to_string(),
            content: vec![ToolContent::text(content)],
            is_error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            result_type: "tool_result".to_string(),
            content: vec![ToolContent::text(message)],
            is_error: Some(true),
        }
    }

    pub fn json(value: Value) -> Self {
        Self {
            result_type: "tool_result".to_string(),
            content: vec![ToolContent::json(value)],
            is_error: None,
        }
    }
}

/// Tool content block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ToolContent {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content_type: "text".to_string(),
            text: Some(content.into()),
            data: None,
        }
    }

    pub fn json(value: Value) -> Self {
        Self {
            content_type: "json".to_string(),
            text: None,
            data: Some(value),
        }
    }
}

/// Server capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            tools: ToolsCapability { list_changed: false },
        }
    }
}

/// Server info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "gently-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = McpRequest::new("tools/list")
            .with_id(1)
            .with_params(serde_json::json!({}));

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("tools/list"));
    }

    #[test]
    fn test_response_success() {
        let resp = McpResponse::success(
            Some(Value::Number(1.into())),
            serde_json::json!({"status": "ok"}),
        );

        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_response_error() {
        let resp = McpResponse::error(
            Some(Value::Number(1.into())),
            error_codes::METHOD_NOT_FOUND,
            "Method not found",
        );

        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
    }
}
