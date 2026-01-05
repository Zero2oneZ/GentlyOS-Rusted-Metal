//! GentlyOS MCP Tools
//!
//! Tools that Claude can invoke through the MCP protocol.

use crate::protocol::{Tool, ToolCall, ToolResult};
use crate::{Error, Result};
use gently_feed::{FeedStorage, ItemKind, LivingFeed};
use gently_search::{ContextRouter, Thought, ThoughtIndex};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A GentlyOS tool implementation
pub trait GentlyTool: Send + Sync {
    /// Get tool definition
    fn definition(&self) -> Tool;

    /// Execute the tool
    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult>;

    /// Whether this tool requires Dance verification
    fn requires_dance(&self) -> bool {
        false
    }
}

/// Shared context for tool execution
pub struct ToolContext {
    pub feed: Arc<RwLock<LivingFeed>>,
    pub index: Arc<RwLock<ThoughtIndex>>,
    pub dance_verified: bool,
}

impl ToolContext {
    pub fn new() -> Self {
        Self {
            feed: Arc::new(RwLock::new(LivingFeed::new())),
            index: Arc::new(RwLock::new(ThoughtIndex::new())),
            dance_verified: false,
        }
    }

    pub fn load() -> Result<Self> {
        // Try to load feed from disk
        let feed = match FeedStorage::default_location() {
            Ok(storage) => storage.load().unwrap_or_else(|_| LivingFeed::new()),
            Err(_) => LivingFeed::new(),
        };

        // Try to load index from disk
        let index_path = ThoughtIndex::default_path();
        let index = ThoughtIndex::load(&index_path).unwrap_or_else(|_| ThoughtIndex::new());

        Ok(Self {
            feed: Arc::new(RwLock::new(feed)),
            index: Arc::new(RwLock::new(index)),
            dance_verified: false,
        })
    }

    pub fn save(&self) -> Result<()> {
        // Save feed
        if let Ok(storage) = FeedStorage::default_location() {
            let feed = self.feed.read().unwrap();
            storage.save(&feed).map_err(|e| Error::ExecutionError(e.to_string()))?;
        }

        // Save index
        let index = self.index.read().unwrap();
        let _ = index.save(ThoughtIndex::default_path());

        Ok(())
    }
}

impl Default for ToolContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry of available tools
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn GentlyTool>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Create with default GentlyOS tools
    pub fn new() -> Self {
        let mut registry = Self {
            tools: HashMap::new(),
        };

        // Register all default tools
        registry.register(Box::new(LivingFeedShow));
        registry.register(Box::new(LivingFeedBoost));
        registry.register(Box::new(LivingFeedAdd));
        registry.register(Box::new(LivingFeedStep));
        registry.register(Box::new(ThoughtAdd));
        registry.register(Box::new(ThoughtSearch));
        registry.register(Box::new(DanceInitiate));
        registry.register(Box::new(IdentityVerify));

        // Register BBBCP/Alexandria tools
        crate::bbbcp_tools::register_bbbcp_tools(&mut registry);

        registry
    }

    /// Register a tool
    pub fn register(&mut self, tool: Box<dyn GentlyTool>) {
        let name = tool.definition().name.clone();
        self.tools.insert(name, tool);
    }

    /// Get all tool definitions
    pub fn definitions(&self) -> Vec<Tool> {
        self.tools.values().map(|t| t.definition()).collect()
    }

    /// Execute a tool
    pub fn execute(&self, call: &ToolCall, ctx: &ToolContext) -> Result<ToolResult> {
        let tool = self
            .tools
            .get(&call.name)
            .ok_or_else(|| Error::ToolNotFound(call.name.clone()))?;

        // Check if Dance is required
        if tool.requires_dance() && !ctx.dance_verified {
            return Err(Error::DanceRequired);
        }

        tool.execute(call.arguments.clone(), ctx)
    }

    /// Get tool by name
    pub fn get(&self, name: &str) -> Option<&dyn GentlyTool> {
        self.tools.get(name).map(|t| t.as_ref())
    }
}

// ============== Living Feed Tools ==============

/// Show the current Living Feed state
pub struct LivingFeedShow;

impl GentlyTool for LivingFeedShow {
    fn definition(&self) -> Tool {
        Tool::new(
            "living_feed_show",
            "Show the current Living Feed state with hot/active/cooling items",
        )
        .with_schema(json!({
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Filter by state: hot, active, cooling, frozen, all",
                    "enum": ["hot", "active", "cooling", "frozen", "all"]
                }
            },
            "required": []
        }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let feed = ctx.feed.read().unwrap();
        let filter = args.get("filter").and_then(|v| v.as_str()).unwrap_or("all");

        let items: Vec<Value> = match filter {
            "hot" => feed.hot_items(),
            "active" => feed.active_items(),
            "cooling" => feed.cooling_items(),
            "frozen" => feed.frozen_items(),
            _ => feed.items().iter().filter(|i| !i.archived).collect(),
        }
        .iter()
        .map(|item| {
            json!({
                "name": item.name,
                "charge": item.charge,
                "state": format!("{:?}", item.state),
                "tags": item.tags,
                "pending_steps": item.pending_steps().len()
            })
        })
        .collect();

        Ok(ToolResult::json(json!({
            "items": items,
            "count": items.len(),
            "xor_chain": feed.xor_chain().render()
        })))
    }
}

/// Boost an item's charge
pub struct LivingFeedBoost;

impl GentlyTool for LivingFeedBoost {
    fn definition(&self) -> Tool {
        Tool::new("living_feed_boost", "Boost an item's charge in the Living Feed")
            .with_schema(json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the item to boost"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Amount to boost (0.1-1.0)",
                        "minimum": 0.1,
                        "maximum": 1.0
                    }
                },
                "required": ["name"]
            }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("name is required".into()))?;

        let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.3) as f32;

        let mut feed = ctx.feed.write().unwrap();
        if feed.boost(name, amount) {
            let item = feed.get_item_by_name(name).unwrap();
            Ok(ToolResult::json(json!({
                "success": true,
                "name": item.name,
                "new_charge": item.charge,
                "state": format!("{:?}", item.state)
            })))
        } else {
            Ok(ToolResult::error(format!("Item '{}' not found", name)))
        }
    }
}

/// Add a new item to the feed
pub struct LivingFeedAdd;

impl GentlyTool for LivingFeedAdd {
    fn definition(&self) -> Tool {
        Tool::new("living_feed_add", "Add a new item to the Living Feed")
            .with_schema(json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the new item"
                    },
                    "kind": {
                        "type": "string",
                        "description": "Kind of item",
                        "enum": ["project", "task", "idea", "reference", "person"]
                    },
                    "tags": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Tags for the item"
                    }
                },
                "required": ["name"]
            }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("name is required".into()))?;

        let kind = match args.get("kind").and_then(|v| v.as_str()) {
            Some("project") => ItemKind::Project,
            Some("task") => ItemKind::Task,
            Some("idea") => ItemKind::Idea,
            Some("reference") => ItemKind::Reference,
            Some("person") => ItemKind::Person,
            _ => ItemKind::Project,
        };

        let mut feed = ctx.feed.write().unwrap();

        // Check if already exists
        if feed.get_item_by_name(name).is_some() {
            return Ok(ToolResult::error(format!("Item '{}' already exists", name)));
        }

        let id = feed.add_item(name, kind);

        // Add tags if provided
        if let Some(tags) = args.get("tags").and_then(|v| v.as_array()) {
            if let Some(item) = feed.get_item_mut(id) {
                for tag in tags {
                    if let Some(t) = tag.as_str() {
                        item.add_tag(t);
                    }
                }
            }
        }

        Ok(ToolResult::json(json!({
            "success": true,
            "id": id.to_string(),
            "name": name,
            "message": format!("Added '{}' to feed", name)
        })))
    }
}

/// Add a step to an item
pub struct LivingFeedStep;

impl GentlyTool for LivingFeedStep {
    fn definition(&self) -> Tool {
        Tool::new("living_feed_step", "Add a step/TODO to a feed item")
            .with_schema(json!({
                "type": "object",
                "properties": {
                    "item": {
                        "type": "string",
                        "description": "Name of the item to add step to"
                    },
                    "step": {
                        "type": "string",
                        "description": "The step content"
                    }
                },
                "required": ["item", "step"]
            }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let item_name = args
            .get("item")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("item is required".into()))?;

        let step_content = args
            .get("step")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("step is required".into()))?;

        let mut feed = ctx.feed.write().unwrap();

        if let Some(step_id) = feed.add_step(item_name, step_content) {
            Ok(ToolResult::json(json!({
                "success": true,
                "step_id": step_id,
                "item": item_name,
                "step": step_content
            })))
        } else {
            Ok(ToolResult::error(format!("Item '{}' not found", item_name)))
        }
    }
}

// ============== Thought Index Tools ==============

/// Add a thought to the index
pub struct ThoughtAdd;

impl GentlyTool for ThoughtAdd {
    fn definition(&self) -> Tool {
        Tool::new("thought_add", "Add a thought to the Thought Index")
            .with_schema(json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The thought content"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source of the thought (file, conversation, etc.)"
                    },
                    "tags": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Tags for the thought"
                    }
                },
                "required": ["content"]
            }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("content is required".into()))?;

        let mut thought = if let Some(source) = args.get("source").and_then(|v| v.as_str()) {
            Thought::with_source(content, source)
        } else {
            Thought::new(content)
        };

        // Add tags
        if let Some(tags) = args.get("tags").and_then(|v| v.as_array()) {
            for tag in tags {
                if let Some(t) = tag.as_str() {
                    thought.add_tag(t);
                }
            }
        }

        let mut index = ctx.index.write().unwrap();
        let id = index.add_thought(thought.clone());

        Ok(ToolResult::json(json!({
            "success": true,
            "id": id.to_string(),
            "address": thought.address,
            "domain": thought.shape.domain,
            "kind": format!("{:?}", thought.shape.kind)
        })))
    }
}

/// Search the thought index
pub struct ThoughtSearch;

impl GentlyTool for ThoughtSearch {
    fn definition(&self) -> Tool {
        Tool::new("thought_search", "Search the Thought Index")
            .with_schema(json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results",
                        "minimum": 1,
                        "maximum": 50
                    },
                    "use_feed_context": {
                        "type": "boolean",
                        "description": "Boost results based on Living Feed context"
                    }
                },
                "required": ["query"]
            }))
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("query is required".into()))?;

        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        let use_feed = args
            .get("use_feed_context")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let index = ctx.index.read().unwrap();
        let feed = ctx.feed.read().unwrap();

        let router = ContextRouter::new()
            .with_max_results(limit)
            .with_feed_boost(use_feed);

        let results = if use_feed {
            router.search(query, &index, Some(&feed))
        } else {
            router.search(query, &index, None)
        };

        let results_json: Vec<Value> = results
            .iter()
            .map(|r| {
                json!({
                    "id": r.thought.id.to_string(),
                    "content": r.thought.content,
                    "score": r.score,
                    "domain": r.thought.shape.domain,
                    "kind": format!("{:?}", r.thought.shape.kind),
                    "match_reason": format!("{:?}", r.match_reason),
                    "wormholes": r.wormholes.len()
                })
            })
            .collect();

        Ok(ToolResult::json(json!({
            "query": query,
            "results": results_json,
            "count": results_json.len(),
            "index_stats": index.stats().to_string()
        })))
    }
}

// ============== Dance Protocol Tools ==============

/// Initiate Dance handshake
pub struct DanceInitiate;

impl GentlyTool for DanceInitiate {
    fn definition(&self) -> Tool {
        Tool::new(
            "dance_initiate",
            "Initiate a Dance Protocol handshake for secure verification",
        )
        .with_schema(json!({
            "type": "object",
            "properties": {
                "purpose": {
                    "type": "string",
                    "description": "Purpose of the Dance session"
                }
            },
            "required": []
        }))
    }

    fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        let purpose = args
            .get("purpose")
            .and_then(|v| v.as_str())
            .unwrap_or("identity verification");

        // In a real implementation, this would start the Dance protocol
        // For now, return a placeholder
        Ok(ToolResult::json(json!({
            "status": "initiated",
            "purpose": purpose,
            "message": "Dance handshake initiated. Please complete verification on your device.",
            "session_id": uuid::Uuid::new_v4().to_string()
        })))
    }
}

/// Verify identity via Dance
pub struct IdentityVerify;

impl GentlyTool for IdentityVerify {
    fn definition(&self) -> Tool {
        Tool::new(
            "identity_verify",
            "Verify identity using Dance Protocol (requires second device)",
        )
        .with_schema(json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Dance session ID to verify"
                }
            },
            "required": ["session_id"]
        }))
    }

    fn requires_dance(&self) -> bool {
        true
    }

    fn execute(&self, args: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let session_id = args
            .get("session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidParameters("session_id is required".into()))?;

        // This would check if the Dance was completed
        // For now, return based on dance_verified flag
        if ctx.dance_verified {
            Ok(ToolResult::json(json!({
                "verified": true,
                "session_id": session_id,
                "message": "Identity verified via Dance Protocol"
            })))
        } else {
            Ok(ToolResult::json(json!({
                "verified": false,
                "session_id": session_id,
                "message": "Dance verification pending"
            })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry() {
        let registry = ToolRegistry::new();
        let defs = registry.definitions();

        assert!(!defs.is_empty());
        assert!(defs.iter().any(|t| t.name == "living_feed_show"));
        assert!(defs.iter().any(|t| t.name == "thought_search"));
    }

    #[test]
    fn test_feed_show() {
        let ctx = ToolContext::new();
        let tool = LivingFeedShow;

        let result = tool.execute(json!({}), &ctx).unwrap();
        assert!(!result.is_error.unwrap_or(false));
    }

    #[test]
    fn test_feed_add() {
        let ctx = ToolContext::new();
        let tool = LivingFeedAdd;

        let result = tool
            .execute(
                json!({
                    "name": "Test Project",
                    "kind": "project"
                }),
                &ctx,
            )
            .unwrap();

        assert!(!result.is_error.unwrap_or(false));
    }
}
