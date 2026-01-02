//! MCP Tools for IPFS Operations
//!
//! Interface and API - they call, we execute.

use crate::{ContentAddress, IpfsClient, IpfsOps, Result};
use crate::operations::{ThoughtData, EmbeddingData, SessionData, SkillData};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// IPFS MCP Tool definitions
pub struct IpfsMcpTools {
    ops: IpfsOps,
}

impl IpfsMcpTools {
    pub fn new(client: IpfsClient) -> Self {
        Self {
            ops: IpfsOps::new(client),
        }
    }

    /// Get tool definitions for MCP registration
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "ipfs_store_thought".into(),
                description: "Store a thought on IPFS".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "content": { "type": "string", "description": "Thought content" },
                        "chain": { "type": "integer", "description": "72-chain assignment (0-71)" }
                    },
                    "required": ["content", "chain"]
                }),
            },
            ToolDefinition {
                name: "ipfs_store_embedding".into(),
                description: "Store a code embedding on IPFS".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "code": { "type": "string", "description": "Code snippet" },
                        "embedding": { "type": "array", "items": { "type": "number" } }
                    },
                    "required": ["code", "embedding"]
                }),
            },
            ToolDefinition {
                name: "ipfs_store_session".into(),
                description: "Store session state for hydration".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "feed_state": { "type": "object" },
                        "thought_index": { "type": "object" }
                    },
                    "required": ["feed_state", "thought_index"]
                }),
            },
            ToolDefinition {
                name: "ipfs_gather".into(),
                description: "Gather content from multiple CIDs".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "cids": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["cids"]
                }),
            },
            ToolDefinition {
                name: "ipfs_retrieve".into(),
                description: "Retrieve content by CID".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "cid": { "type": "string", "description": "Content ID" }
                    },
                    "required": ["cid"]
                }),
            },
            ToolDefinition {
                name: "ipfs_pin".into(),
                description: "Pin content to ensure persistence".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "cid": { "type": "string" },
                        "remote": { "type": "boolean", "default": false },
                        "service": { "type": "string" }
                    },
                    "required": ["cid"]
                }),
            },
        ]
    }

    /// Execute a tool call
    pub async fn execute(&self, name: &str, args: Value) -> Result<ToolResult> {
        match name {
            "ipfs_store_thought" => self.store_thought(args).await,
            "ipfs_store_embedding" => self.store_embedding(args).await,
            "ipfs_store_session" => self.store_session(args).await,
            "ipfs_gather" => self.gather(args).await,
            "ipfs_retrieve" => self.retrieve(args).await,
            "ipfs_pin" => self.pin(args).await,
            _ => Ok(ToolResult::error(format!("Unknown tool: {}", name))),
        }
    }

    async fn store_thought(&self, args: Value) -> Result<ToolResult> {
        let content = args["content"].as_str().unwrap_or("");
        let chain = args["chain"].as_u64().unwrap_or(0) as u8;

        let thought = ThoughtData {
            id: uuid::Uuid::new_v4().to_string(),
            content: content.to_string(),
            chain,
            embedding: vec![], // Would be filled by embedder
            timestamp: timestamp_now(),
        };

        let address = self.ops.store_thought(&thought).await?;

        Ok(ToolResult::success(json!({
            "cid": address.cid,
            "content_type": "thought",
            "encrypted": address.encrypted
        })))
    }

    async fn store_embedding(&self, args: Value) -> Result<ToolResult> {
        let code = args["code"].as_str().unwrap_or("");
        let embedding: Vec<f32> = args["embedding"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_f64().map(|f| f as f32)).collect())
            .unwrap_or_default();

        let data = EmbeddingData {
            id: uuid::Uuid::new_v4().to_string(),
            code: code.to_string(),
            embedding,
            chain: 0, // Would be computed
            feedback_score: 0.0,
        };

        let address = self.ops.store_embedding(&data).await?;

        Ok(ToolResult::success(json!({
            "cid": address.cid,
            "content_type": "embedding",
            "encrypted": address.encrypted
        })))
    }

    async fn store_session(&self, args: Value) -> Result<ToolResult> {
        let session = SessionData {
            session_id: uuid::Uuid::new_v4().to_string(),
            feed_state: args["feed_state"].clone(),
            thought_index: args["thought_index"].clone(),
            timestamp: timestamp_now(),
        };

        let address = self.ops.store_session(&session).await?;

        Ok(ToolResult::success(json!({
            "cid": address.cid,
            "content_type": "session_state",
            "encrypted": address.encrypted,
            "session_id": session.session_id
        })))
    }

    async fn gather(&self, args: Value) -> Result<ToolResult> {
        let cids: Vec<String> = args["cids"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let results = self.ops.gather(&cids).await?;

        let gathered: Vec<Value> = results
            .iter()
            .map(|r| json!({
                "cid": r.cid,
                "success": r.success,
                "error": r.error
            }))
            .collect();

        Ok(ToolResult::success(json!({
            "gathered": gathered,
            "success_count": results.iter().filter(|r| r.success).count(),
            "total": results.len()
        })))
    }

    async fn retrieve(&self, args: Value) -> Result<ToolResult> {
        let cid = args["cid"].as_str().unwrap_or("");

        // Would retrieve from IPFS
        Ok(ToolResult::success(json!({
            "cid": cid,
            "status": "not_implemented",
            "message": "Content retrieval pending IPFS connection"
        })))
    }

    async fn pin(&self, args: Value) -> Result<ToolResult> {
        let cid = args["cid"].as_str().unwrap_or("");
        let remote = args["remote"].as_bool().unwrap_or(false);
        let service = args["service"].as_str();

        if remote {
            if let Some(svc) = service {
                self.ops.client().pin_remote(cid, svc).await?;
                Ok(ToolResult::success(json!({
                    "cid": cid,
                    "pinned": true,
                    "location": "remote",
                    "service": svc
                })))
            } else {
                Ok(ToolResult::error("Service required for remote pinning"))
            }
        } else {
            self.ops.client().pin(cid).await?;
            Ok(ToolResult::success(json!({
                "cid": cid,
                "pinned": true,
                "location": "local"
            })))
        }
    }
}

/// Tool definition for MCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub content: Value,
    pub error: Option<String>,
}

impl ToolResult {
    pub fn success(content: Value) -> Self {
        Self {
            success: true,
            content,
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            content: json!({}),
            error: Some(msg.into()),
        }
    }
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
