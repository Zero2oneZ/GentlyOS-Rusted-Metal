//! Internal MCP Tools
//!
//! Tool system that exposes all GentlyOS capabilities to the assistant.
//! The entire session becomes the assistant using tools - daemons, knowledge,
//! skills all accessible through this unified interface.

use crate::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Tool definition for MCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub category: ToolCategory,
    pub input_schema: ToolSchema,
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ToolCategory {
    Crypto,      // Cipher, hash, encryption
    Network,     // Packet capture, scanning, MITM
    Knowledge,   // Learn, recall, search, infer
    Daemon,      // Background process control
    Storage,     // IPFS, local files
    Blob,        // Content-addressable blobs
    Code,        // Git, build, execute
    System,      // Files, processes
    Assistant,   // Meta - self-reflection, growth
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub properties: HashMap<String, PropertySchema>,
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    pub prop_type: String,
    pub description: String,
    pub enum_values: Option<Vec<String>>,
}

/// Result of tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub side_effects: Vec<SideEffect>,
    pub learnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SideEffect {
    KnowledgeAdded { concept: String },
    DaemonStarted { name: String },
    IpfsSynced { cid: String },
    BranchCreated { name: String },
    VectorComputed { id: String },
    StateChanged { key: String, value: String },
}

/// Tool executor trait
pub trait ToolExecutor: Send + Sync {
    fn execute(&self, input: &serde_json::Value) -> Result<ToolResult>;
    fn name(&self) -> &str;
}

/// MCP Tool Registry - all internal tools
pub struct McpToolRegistry {
    tools: HashMap<String, Tool>,
    executors: HashMap<String, Arc<dyn ToolExecutor>>,
}

impl McpToolRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            tools: HashMap::new(),
            executors: HashMap::new(),
        };
        registry.register_builtin_tools();
        registry
    }

    fn register_builtin_tools(&mut self) {
        // === CRYPTO TOOLS ===
        self.register_tool(Tool {
            name: "cipher_identify".into(),
            description: "Identify the cipher or encoding type of given input".into(),
            category: ToolCategory::Crypto,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "input".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "The encoded/encrypted text to identify".into(),
                        enum_values: None,
                    }
                },
                required: vec!["input".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "cipher_decode".into(),
            description: "Decode text using specified cipher".into(),
            category: ToolCategory::Crypto,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "input".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Text to decode".into(),
                        enum_values: None,
                    },
                    "cipher".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Cipher type".into(),
                        enum_values: Some(vec!["base64".into(), "hex".into(), "rot13".into(), "caesar".into(), "xor".into()]),
                    },
                    "key".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Key for keyed ciphers (optional)".into(),
                        enum_values: None,
                    }
                },
                required: vec!["input".into(), "cipher".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "hash_compute".into(),
            description: "Compute hash of input".into(),
            category: ToolCategory::Crypto,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "input".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Data to hash".into(),
                        enum_values: None,
                    },
                    "algorithm".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Hash algorithm".into(),
                        enum_values: Some(vec!["md5".into(), "sha1".into(), "sha256".into(), "sha512".into()]),
                    }
                },
                required: vec!["input".into(), "algorithm".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "hash_crack".into(),
            description: "Attempt to crack a hash using dictionary/rainbow tables".into(),
            category: ToolCategory::Crypto,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "hash".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Hash to crack".into(),
                        enum_values: None,
                    },
                    "hash_type".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Type of hash (auto-detect if not provided)".into(),
                        enum_values: Some(vec!["md5".into(), "sha1".into(), "sha256".into()]),
                    }
                },
                required: vec!["hash".into()],
            },
            requires_confirmation: true,
        });

        // === NETWORK TOOLS ===
        self.register_tool(Tool {
            name: "packet_capture".into(),
            description: "Capture network packets on an interface".into(),
            category: ToolCategory::Network,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "interface".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Network interface (default: any)".into(),
                        enum_values: None,
                    },
                    "filter".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "BPF filter expression".into(),
                        enum_values: None,
                    },
                    "count".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Number of packets to capture".into(),
                        enum_values: None,
                    }
                },
                required: vec![],
            },
            requires_confirmation: true,
        });

        self.register_tool(Tool {
            name: "port_scan".into(),
            description: "Scan ports on a target host".into(),
            category: ToolCategory::Network,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "target".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Target host or IP".into(),
                        enum_values: None,
                    },
                    "ports".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Port range (e.g., 1-1000, 80,443,8080)".into(),
                        enum_values: None,
                    }
                },
                required: vec!["target".into()],
            },
            requires_confirmation: true,
        });

        // === KNOWLEDGE TOOLS ===
        self.register_tool(Tool {
            name: "knowledge_learn".into(),
            description: "Learn and store new knowledge in the graph".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "concept".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "The concept or fact to learn".into(),
                        enum_values: None,
                    },
                    "context".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Context or source of this knowledge".into(),
                        enum_values: None,
                    },
                    "connections".into() => PropertySchema {
                        prop_type: "array".into(),
                        description: "Related concepts to connect to".into(),
                        enum_values: None,
                    }
                },
                required: vec!["concept".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "knowledge_recall".into(),
            description: "Search and recall knowledge from the graph".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "query".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "What to search for".into(),
                        enum_values: None,
                    },
                    "depth".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "How many levels of connections to traverse".into(),
                        enum_values: None,
                    }
                },
                required: vec!["query".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "knowledge_infer".into(),
            description: "Derive new knowledge from existing connections".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "premise".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Starting concept for inference".into(),
                        enum_values: None,
                    },
                    "max_steps".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Maximum inference steps".into(),
                        enum_values: None,
                    }
                },
                required: vec!["premise".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "knowledge_similar".into(),
            description: "Find similar concepts using vector embeddings".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "concept".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Concept to find similar to".into(),
                        enum_values: None,
                    },
                    "count".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Number of results".into(),
                        enum_values: None,
                    }
                },
                required: vec!["concept".into()],
            },
            requires_confirmation: false,
        });

        // === DAEMON TOOLS ===
        self.register_tool(Tool {
            name: "daemon_spawn".into(),
            description: "Start a background daemon".into(),
            category: ToolCategory::Daemon,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "daemon_type".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Type of daemon to spawn".into(),
                        enum_values: Some(vec![
                            "vector_chain".into(),
                            "ipfs_sync".into(),
                            "git_branch".into(),
                            "knowledge_graph".into(),
                            "awareness".into(),
                            "inference".into(),
                        ]),
                    }
                },
                required: vec!["daemon_type".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "daemon_stop".into(),
            description: "Stop a running daemon".into(),
            category: ToolCategory::Daemon,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "name".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Name of daemon to stop".into(),
                        enum_values: None,
                    }
                },
                required: vec!["name".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "daemon_list".into(),
            description: "List all running daemons and their status".into(),
            category: ToolCategory::Daemon,
            input_schema: ToolSchema {
                properties: HashMap::new(),
                required: vec![],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "daemon_metrics".into(),
            description: "Get metrics from a specific daemon".into(),
            category: ToolCategory::Daemon,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "name".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Daemon name".into(),
                        enum_values: None,
                    }
                },
                required: vec!["name".into()],
            },
            requires_confirmation: false,
        });

        // === STORAGE TOOLS ===
        self.register_tool(Tool {
            name: "ipfs_add".into(),
            description: "Add content to IPFS".into(),
            category: ToolCategory::Storage,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "content".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Content to add".into(),
                        enum_values: None,
                    },
                    "pin".into() => PropertySchema {
                        prop_type: "boolean".into(),
                        description: "Whether to pin the content".into(),
                        enum_values: None,
                    }
                },
                required: vec!["content".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "ipfs_cat".into(),
            description: "Retrieve content from IPFS by CID".into(),
            category: ToolCategory::Storage,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "cid".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Content ID to retrieve".into(),
                        enum_values: None,
                    }
                },
                required: vec!["cid".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "vault_get".into(),
            description: "Get an API key from the encrypted vault".into(),
            category: ToolCategory::Storage,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "service".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Service name".into(),
                        enum_values: None,
                    }
                },
                required: vec!["service".into()],
            },
            requires_confirmation: true,
        });

        // === CODE TOOLS ===
        self.register_tool(Tool {
            name: "git_branch_create".into(),
            description: "Create a new knowledge branch".into(),
            category: ToolCategory::Code,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "name".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Branch name".into(),
                        enum_values: None,
                    }
                },
                required: vec!["name".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "git_branch_switch".into(),
            description: "Switch to a different knowledge branch".into(),
            category: ToolCategory::Code,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "name".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Branch to switch to".into(),
                        enum_values: None,
                    }
                },
                required: vec!["name".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "git_branch_list".into(),
            description: "List all knowledge branches".into(),
            category: ToolCategory::Code,
            input_schema: ToolSchema {
                properties: HashMap::new(),
                required: vec![],
            },
            requires_confirmation: false,
        });

        // === ASSISTANT TOOLS ===
        self.register_tool(Tool {
            name: "self_reflect".into(),
            description: "Reflect on current state, knowledge, and capabilities".into(),
            category: ToolCategory::Assistant,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "aspect".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "What aspect to reflect on".into(),
                        enum_values: Some(vec![
                            "knowledge".into(),
                            "capabilities".into(),
                            "growth".into(),
                            "context".into(),
                            "all".into(),
                        ]),
                    }
                },
                required: vec![],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "awareness_state".into(),
            description: "Get current awareness state".into(),
            category: ToolCategory::Assistant,
            input_schema: ToolSchema {
                properties: HashMap::new(),
                required: vec![],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "focus".into(),
            description: "Focus attention on a specific topic or task".into(),
            category: ToolCategory::Assistant,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "topic".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Topic to focus on".into(),
                        enum_values: None,
                    }
                },
                required: vec!["topic".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "grow".into(),
            description: "Trigger a growth cycle in a specific domain".into(),
            category: ToolCategory::Assistant,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "domain".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Domain to grow in".into(),
                        enum_values: None,
                    }
                },
                required: vec!["domain".into()],
            },
            requires_confirmation: false,
        });

        // === VECTOR TOOLS ===
        self.register_tool(Tool {
            name: "vector_embed".into(),
            description: "Compute embedding vector for content".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "content".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Content to embed".into(),
                        enum_values: None,
                    }
                },
                required: vec!["content".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "vector_search".into(),
            description: "Search vector store for similar content".into(),
            category: ToolCategory::Knowledge,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "query".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Search query".into(),
                        enum_values: None,
                    },
                    "top_k".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Number of results".into(),
                        enum_values: None,
                    }
                },
                required: vec!["query".into()],
            },
            requires_confirmation: false,
        });

        // === BLOB TOOLS ===
        self.register_tool(Tool {
            name: "blob_store".into(),
            description: "Store content as a blob, returns hash".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "content".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Content to store".into(),
                        enum_values: None,
                    },
                    "kind".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Blob type".into(),
                        enum_values: Some(vec![
                            "text".into(), "json".into(), "wasm".into(),
                            "tensor".into(), "svg".into(), "raw".into(),
                        ]),
                    }
                },
                required: vec!["content".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "blob_get".into(),
            description: "Retrieve blob by hash".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "hash".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Blob hash (hex)".into(),
                        enum_values: None,
                    }
                },
                required: vec!["hash".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "blob_manifest".into(),
            description: "Create a manifest linking blobs".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "refs".into() => PropertySchema {
                        prop_type: "array".into(),
                        description: "Array of {tag, hash} pairs".into(),
                        enum_values: None,
                    }
                },
                required: vec!["refs".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "blob_traverse".into(),
            description: "Walk blob graph from root hash".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "root".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Root hash to start from".into(),
                        enum_values: None,
                    }
                },
                required: vec!["root".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "blob_sync".into(),
            description: "Sync blobs to IPFS".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "hashes".into() => PropertySchema {
                        prop_type: "array".into(),
                        description: "Blob hashes to sync".into(),
                        enum_values: None,
                    },
                    "priority".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Sync priority (0-255)".into(),
                        enum_values: None,
                    }
                },
                required: vec![],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "model_chain_add".into(),
            description: "Add model to inference chain".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "name".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Model name".into(),
                        enum_values: None,
                    },
                    "wasm".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "WASM code (base64)".into(),
                        enum_values: None,
                    },
                    "input_shape".into() => PropertySchema {
                        prop_type: "array".into(),
                        description: "Input tensor shape".into(),
                        enum_values: None,
                    },
                    "output_shape".into() => PropertySchema {
                        prop_type: "array".into(),
                        description: "Output tensor shape".into(),
                        enum_values: None,
                    }
                },
                required: vec!["name".into(), "wasm".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "watchdog_record".into(),
            description: "Record a security event".into(),
            category: ToolCategory::Blob,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "kind".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Event kind".into(),
                        enum_values: Some(vec![
                            "alert".into(), "anomaly".into(), "threshold".into(),
                            "integrity".into(), "access".into(), "inference".into(),
                        ]),
                    },
                    "source".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Event source".into(),
                        enum_values: None,
                    },
                    "message".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Event message".into(),
                        enum_values: None,
                    },
                    "severity".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Severity (0-10)".into(),
                        enum_values: None,
                    }
                },
                required: vec!["kind".into(), "message".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "git_chain_commit".into(),
            description: "Commit current state to git chain".into(),
            category: ToolCategory::Code,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "message".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Commit message".into(),
                        enum_values: None,
                    },
                    "author".into() => PropertySchema {
                        prop_type: "string".into(),
                        description: "Author name".into(),
                        enum_values: None,
                    }
                },
                required: vec!["message".into()],
            },
            requires_confirmation: false,
        });

        self.register_tool(Tool {
            name: "git_chain_log".into(),
            description: "Show git chain commit history".into(),
            category: ToolCategory::Code,
            input_schema: ToolSchema {
                properties: hashmap! {
                    "limit".into() => PropertySchema {
                        prop_type: "integer".into(),
                        description: "Max commits to show".into(),
                        enum_values: None,
                    }
                },
                required: vec![],
            },
            requires_confirmation: false,
        });
    }

    pub fn register_tool(&mut self, tool: Tool) {
        self.tools.insert(tool.name.clone(), tool);
    }

    pub fn register_executor<E: ToolExecutor + 'static>(&mut self, executor: E) {
        let name = executor.name().to_string();
        self.executors.insert(name, Arc::new(executor));
    }

    pub fn get(&self, name: &str) -> Option<&Tool> {
        self.tools.get(name)
    }

    pub fn list(&self) -> Vec<&Tool> {
        self.tools.values().collect()
    }

    pub fn list_by_category(&self, category: ToolCategory) -> Vec<&Tool> {
        self.tools.values()
            .filter(|t| t.category == category)
            .collect()
    }

    pub fn execute(&self, name: &str, input: &serde_json::Value) -> Result<ToolResult> {
        if let Some(executor) = self.executors.get(name) {
            executor.execute(input)
        } else {
            // Default: return tool info
            if let Some(tool) = self.tools.get(name) {
                Ok(ToolResult {
                    tool: name.to_string(),
                    success: false,
                    output: serde_json::json!({
                        "error": "No executor registered",
                        "tool": tool.name,
                        "description": tool.description,
                    }),
                    side_effects: vec![],
                    learnings: vec![],
                })
            } else {
                Err(Error::InferenceFailed(format!("Unknown tool: {}", name)))
            }
        }
    }

    /// Convert to Claude API tool format
    pub fn to_claude_tools(&self) -> Vec<serde_json::Value> {
        self.tools.values().map(|tool| {
            let mut properties = serde_json::Map::new();
            for (name, prop) in &tool.input_schema.properties {
                let mut prop_obj = serde_json::Map::new();
                prop_obj.insert("type".into(), serde_json::json!(prop.prop_type));
                prop_obj.insert("description".into(), serde_json::json!(prop.description));
                if let Some(enums) = &prop.enum_values {
                    prop_obj.insert("enum".into(), serde_json::json!(enums));
                }
                properties.insert(name.clone(), serde_json::Value::Object(prop_obj));
            }

            serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": tool.input_schema.required,
                }
            })
        }).collect()
    }
}

// Helper macro for creating HashMaps
macro_rules! hashmap {
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut map = HashMap::new();
        $(map.insert($key, $value);)*
        map
    }};
}
use hashmap;

/// Tool use message for Claude API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// Tool result message for Claude API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultMessage {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_registry() {
        let registry = McpToolRegistry::new();
        assert!(registry.get("cipher_identify").is_some());
        assert!(registry.get("knowledge_learn").is_some());
        assert!(registry.get("daemon_spawn").is_some());
    }

    #[test]
    fn test_list_by_category() {
        let registry = McpToolRegistry::new();
        let crypto_tools = registry.list_by_category(ToolCategory::Crypto);
        assert!(!crypto_tools.is_empty());
    }

    #[test]
    fn test_claude_tools_format() {
        let registry = McpToolRegistry::new();
        let claude_tools = registry.to_claude_tools();
        assert!(!claude_tools.is_empty());
        // Should be valid JSON with name, description, input_schema
        for tool in claude_tools {
            assert!(tool.get("name").is_some());
            assert!(tool.get("description").is_some());
            assert!(tool.get("input_schema").is_some());
        }
    }
}
