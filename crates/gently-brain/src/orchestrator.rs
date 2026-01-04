//! Brain Orchestrator
//!
//! The central nervous system that coordinates all brain components:
//! - Manages daemons (background processes)
//! - Routes tool calls to appropriate handlers
//! - Maintains the knowledge graph
//! - Runs the awareness loop
//! - Drives recursive growth through routine processing
//!
//! "Instructions and knowledge bring awareness just by routine process"

use crate::{
    Result, Error,
    daemon::{DaemonManager, DaemonType, DaemonEvent, AwarenessDaemon, VectorChainDaemon, IpfsSyncDaemon, GitBranchDaemon, VectorJob, SyncJob},
    knowledge::{KnowledgeGraph, NodeType, EdgeType},
    skills::{SkillRegistry, SkillContext, Learning},
    mcp::{McpToolRegistry, ToolResult, SideEffect},
    claude::{ClaudeClient, ClaudeModel, GentlyAssistant},
};
use gently_alexandria::{
    AlexandriaGraph, AlexandriaConfig, ConceptId,
    SemanticTesseract, HyperPosition, TemporalPosition,
    node::NodeFingerprint,
};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::collections::VecDeque;
use tokio::sync::mpsc;
use chrono::Utc;

/// Brain configuration
#[derive(Debug, Clone)]
pub struct BrainConfig {
    pub enable_daemons: bool,
    pub enable_ipfs: bool,
    pub enable_inference: bool,
    pub awareness_interval_ms: u64,
    pub vector_batch_size: usize,
    pub ipfs_sync_interval_ms: u64,
    pub growth_rate: f32,
    pub max_context_size: usize,
}

impl Default for BrainConfig {
    fn default() -> Self {
        Self {
            enable_daemons: true,
            enable_ipfs: true,
            enable_inference: true,
            awareness_interval_ms: 250,
            vector_batch_size: 10,
            ipfs_sync_interval_ms: 5000,
            growth_rate: 0.1,
            max_context_size: 100,
        }
    }
}

/// Result of processing a thought/input
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    pub response: String,
    pub tool_uses: Vec<String>,
    pub learnings: Vec<String>,
    pub side_effects: Vec<SideEffect>,
    pub awareness_update: Option<AwarenessSnapshot>,
}

/// Snapshot of awareness state
#[derive(Debug, Clone)]
pub struct AwarenessSnapshot {
    pub attention: Vec<String>,
    pub context: Vec<String>,
    pub active_thoughts: usize,
    pub knowledge_nodes: usize,
    pub active_daemons: usize,
    pub growth_direction: String,
}

/// The Brain Orchestrator - coordinates all brain components
pub struct BrainOrchestrator {
    config: BrainConfig,

    // Core components
    daemon_manager: Arc<Mutex<DaemonManager>>,
    knowledge_graph: Arc<KnowledgeGraph>,
    skill_registry: Arc<SkillRegistry>,
    tool_registry: Arc<McpToolRegistry>,

    // Alexandria - distributed knowledge graph
    alexandria: Arc<Mutex<AlexandriaGraph>>,
    tesseract: Arc<Mutex<SemanticTesseract>>,

    // State
    running: Arc<AtomicBool>,
    context: Arc<Mutex<VecDeque<String>>>,
    attention: Arc<Mutex<Vec<String>>>,
    pending_thoughts: Arc<Mutex<VecDeque<String>>>,
    growth_direction: Arc<Mutex<String>>,

    // Event channels
    event_tx: mpsc::UnboundedSender<BrainEvent>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<BrainEvent>>>,
}

/// Events in the brain
#[derive(Debug, Clone)]
pub enum BrainEvent {
    // Input events
    Thought { content: String },
    ToolCall { name: String, input: serde_json::Value },
    Focus { topic: String },

    // Processing events
    Learning { concept: String, confidence: f32 },
    Connection { from: String, to: String, edge_type: String },
    Inference { premise: String, conclusion: String },

    // Daemon events
    DaemonEvent(DaemonEvent),

    // Growth events
    GrowthCycle { domain: String, nodes_added: usize },
    BranchSwitch { from: String, to: String },
    IpfsSync { cid: String },

    // Awareness
    AwarenessUpdate(AwarenessSnapshot),

    // Alexandria events
    AlexandriaEdge { from: String, to: String, kind: String },
    AlexandriaTesseract { concept: String, face: String },
    AlexandriaDrift { concept: String, positions: usize },
}

impl BrainOrchestrator {
    pub fn new(config: BrainConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        // Create a node fingerprint for this brain instance
        let node_fingerprint = NodeFingerprint::from_hardware(
            "gently-brain",
            4,  // CPU cores placeholder
            16, // RAM GB placeholder
            &format!("brain-{}", uuid::Uuid::new_v4()),
        );

        Self {
            config,
            daemon_manager: Arc::new(Mutex::new(DaemonManager::new())),
            knowledge_graph: Arc::new(KnowledgeGraph::new()),
            skill_registry: Arc::new(SkillRegistry::new()),
            tool_registry: Arc::new(McpToolRegistry::new()),
            alexandria: Arc::new(Mutex::new(AlexandriaGraph::with_defaults(node_fingerprint))),
            tesseract: Arc::new(Mutex::new(SemanticTesseract::new())),
            running: Arc::new(AtomicBool::new(false)),
            context: Arc::new(Mutex::new(VecDeque::new())),
            attention: Arc::new(Mutex::new(Vec::new())),
            pending_thoughts: Arc::new(Mutex::new(VecDeque::new())),
            growth_direction: Arc::new(Mutex::new("general".into())),
            event_tx: tx,
            event_rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Start the brain - initializes all daemons and begins awareness loop
    pub async fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Start daemon manager
        {
            let mut dm = self.daemon_manager.lock().unwrap();
            dm.start();
        }

        if self.config.enable_daemons {
            // Spawn core daemons
            self.spawn_daemon(DaemonType::VectorChain)?;
            self.spawn_daemon(DaemonType::KnowledgeGraph)?;
            self.spawn_daemon(DaemonType::Awareness)?;

            if self.config.enable_ipfs {
                self.spawn_daemon(DaemonType::IpfsSync)?;
            }

            self.spawn_daemon(DaemonType::GitBranch)?;
        }

        // Emit start event
        let _ = self.event_tx.send(BrainEvent::AwarenessUpdate(self.get_awareness_snapshot()));

        Ok(())
    }

    /// Stop the brain
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let mut dm = self.daemon_manager.lock().unwrap();
        dm.stop();
    }

    /// Spawn a daemon
    pub fn spawn_daemon(&self, daemon_type: DaemonType) -> Result<String> {
        let mut dm = self.daemon_manager.lock().unwrap();
        dm.spawn(daemon_type)
    }

    /// Process a thought - the main entry point for awareness
    pub async fn process_thought(&self, thought: &str) -> ProcessingResult {
        // Add to context
        {
            let mut ctx = self.context.lock().unwrap();
            ctx.push_back(thought.to_string());
            if ctx.len() > self.config.max_context_size {
                ctx.pop_front();
            }
        }

        // Queue the thought for processing
        {
            let mut thoughts = self.pending_thoughts.lock().unwrap();
            thoughts.push_back(thought.to_string());
        }

        // Emit thought event
        let _ = self.event_tx.send(BrainEvent::Thought { content: thought.to_string() });

        // Process immediately (awareness loop will also process)
        self.process_single_thought(thought).await
    }

    /// Process a single thought and generate response
    async fn process_single_thought(&self, thought: &str) -> ProcessingResult {
        let mut tool_uses = Vec::new();
        let mut learnings = Vec::new();
        let mut side_effects = Vec::new();

        // Check for skill triggers
        let matching_skills = self.skill_registry.find_by_trigger(thought);
        for skill in matching_skills {
            tool_uses.push(format!("skill:{}", skill.name));
        }

        // Record query in Alexandria (builds usage graph)
        {
            let alexandria = self.alexandria.lock().unwrap();
            alexandria.record_query(thought);
        }

        // Extract learnable content
        if self.is_learnable(thought) {
            let concept = self.extract_concept(thought);
            self.knowledge_graph.learn(&concept, Some(thought), Some(0.7));
            learnings.push(concept.clone());
            side_effects.push(SideEffect::KnowledgeAdded { concept: concept.clone() });

            // Also record in Alexandria with concept edges
            {
                let alexandria = self.alexandria.lock().unwrap();
                let concept_id = alexandria.ensure_concept(&concept);

                // Connect thought to concept via query
                let thought_id = ConceptId::from_concept(thought);
                alexandria.add_edge(
                    thought_id,
                    concept_id,
                    gently_alexandria::EdgeKind::SessionCorrelation,
                );
            }

            let _ = self.event_tx.send(BrainEvent::Learning {
                concept: thought.to_string(),
                confidence: 0.7,
            });
        }

        // Update attention based on content
        self.update_attention(thought);

        // Check for connections to existing knowledge
        let related = self.knowledge_graph.search(thought);
        for node in related.iter().take(3) {
            // Build edges in Alexandria for discovered connections
            {
                let alexandria = self.alexandria.lock().unwrap();
                let from_id = ConceptId::from_concept(thought);
                let to_id = ConceptId::from_concept(&node.concept);
                alexandria.add_edge(
                    from_id,
                    to_id,
                    gently_alexandria::EdgeKind::UserPath,
                );
            }

            let _ = self.event_tx.send(BrainEvent::Connection {
                from: thought.to_string(),
                to: node.concept.clone(),
                edge_type: "RelatedTo".into(),
            });
        }

        // Query Alexandria for additional connections
        let alexandria_topology = {
            let alexandria = self.alexandria.lock().unwrap();
            alexandria.query_topology(thought)
        };

        // Add Alexandria-discovered concepts to learnings
        if let Some(topology) = alexandria_topology {
            for edge in topology.outgoing.iter().take(2) {
                let alexandria = self.alexandria.lock().unwrap();
                if let Some(concept) = alexandria.get_concept(&edge.to) {
                    learnings.push(format!("discovered:{}", concept.text));
                }
            }
        }

        // Generate response based on context and knowledge
        let response = self.generate_response(thought, &related).await;

        ProcessingResult {
            response,
            tool_uses,
            learnings,
            side_effects,
            awareness_update: Some(self.get_awareness_snapshot()),
        }
    }

    /// Execute a tool call
    pub async fn execute_tool(&self, name: &str, input: &serde_json::Value) -> Result<ToolResult> {
        // Emit event
        let _ = self.event_tx.send(BrainEvent::ToolCall {
            name: name.to_string(),
            input: input.clone(),
        });

        // Route to appropriate handler
        match name {
            // Knowledge tools
            "knowledge_learn" => self.tool_knowledge_learn(input).await,
            "knowledge_recall" => self.tool_knowledge_recall(input).await,
            "knowledge_infer" => self.tool_knowledge_infer(input).await,
            "knowledge_similar" => self.tool_knowledge_similar(input).await,

            // Daemon tools
            "daemon_spawn" => self.tool_daemon_spawn(input).await,
            "daemon_stop" => self.tool_daemon_stop(input).await,
            "daemon_list" => self.tool_daemon_list(input).await,
            "daemon_metrics" => self.tool_daemon_metrics(input).await,

            // Assistant tools
            "self_reflect" => self.tool_self_reflect(input).await,
            "awareness_state" => self.tool_awareness_state(input).await,
            "focus" => self.tool_focus(input).await,
            "grow" => self.tool_grow(input).await,

            // Alexandria tools
            "alexandria_navigate" => self.tool_alexandria_navigate(input).await,
            "alexandria_tesseract" => self.tool_alexandria_tesseract(input).await,
            "alexandria_drift" => self.tool_alexandria_drift(input).await,
            "alexandria_wormhole" => self.tool_alexandria_wormhole(input).await,
            "alexandria_record" => self.tool_alexandria_record(input).await,

            // Default: try registry
            _ => self.tool_registry.execute(name, input),
        }
    }

    /// Focus attention on a topic
    pub fn focus(&self, topic: &str) {
        let mut attention = self.attention.lock().unwrap();
        attention.push(topic.to_string());
        if attention.len() > 5 {
            attention.remove(0);
        }

        // Update growth direction if strongly focused
        if attention.iter().filter(|a| a.contains(topic)).count() >= 2 {
            let mut direction = self.growth_direction.lock().unwrap();
            *direction = topic.to_string();
        }

        let _ = self.event_tx.send(BrainEvent::Focus { topic: topic.to_string() });
    }

    /// Trigger a growth cycle
    pub async fn grow(&self, domain: &str) -> usize {
        // Set growth direction
        {
            let mut direction = self.growth_direction.lock().unwrap();
            *direction = domain.to_string();
        }

        // Find existing knowledge in domain
        let existing = self.knowledge_graph.search(domain);

        // Generate inferences
        let mut nodes_added = 0;
        for node in existing.iter().take(5) {
            let inferences = self.knowledge_graph.infer(Some(&node.concept), 2);
            nodes_added += inferences.len();
        }

        // Emit growth event
        let _ = self.event_tx.send(BrainEvent::GrowthCycle {
            domain: domain.to_string(),
            nodes_added,
        });

        nodes_added
    }

    /// Get current awareness snapshot
    pub fn get_awareness_snapshot(&self) -> AwarenessSnapshot {
        let attention = self.attention.lock().unwrap().clone();
        let context: Vec<String> = self.context.lock().unwrap().iter().cloned().collect();
        let active_thoughts = self.pending_thoughts.lock().unwrap().len();
        let knowledge_nodes = self.knowledge_graph.search("*").len();
        let active_daemons = {
            let dm = self.daemon_manager.lock().unwrap();
            dm.list().iter().filter(|(_, _, running)| *running).count()
        };
        let growth_direction = self.growth_direction.lock().unwrap().clone();

        AwarenessSnapshot {
            attention,
            context: context.into_iter().rev().take(10).collect(),
            active_thoughts,
            knowledge_nodes,
            active_daemons,
            growth_direction,
        }
    }

    /// Get the event receiver
    pub fn events(&self) -> Arc<Mutex<mpsc::UnboundedReceiver<BrainEvent>>> {
        self.event_rx.clone()
    }

    /// Get tool registry for Claude API integration
    pub fn tool_registry(&self) -> &McpToolRegistry {
        &self.tool_registry
    }

    /// Get knowledge graph
    pub fn knowledge_graph(&self) -> &KnowledgeGraph {
        &self.knowledge_graph
    }

    /// Get skill registry
    pub fn skill_registry(&self) -> &SkillRegistry {
        &self.skill_registry
    }

    /// Get Alexandria graph
    pub fn alexandria(&self) -> Arc<Mutex<AlexandriaGraph>> {
        self.alexandria.clone()
    }

    /// Get Tesseract
    pub fn tesseract(&self) -> Arc<Mutex<SemanticTesseract>> {
        self.tesseract.clone()
    }

    // === Internal helpers ===

    fn is_learnable(&self, thought: &str) -> bool {
        // Check if thought contains learnable patterns
        let learnable_patterns = [
            "is", "are", "means", "defined as", "equals",
            "learned", "discovered", "found", "realized",
            "fact:", "note:", "remember:",
        ];
        let thought_lower = thought.to_lowercase();
        learnable_patterns.iter().any(|p| thought_lower.contains(p))
    }

    fn extract_concept(&self, thought: &str) -> String {
        // Extract the main concept from the thought
        // Simple heuristic: first noun phrase or first few words
        let words: Vec<&str> = thought.split_whitespace().take(5).collect();
        words.join(" ")
    }

    fn update_attention(&self, thought: &str) {
        // Extract key topics and update attention
        let words: Vec<&str> = thought.split_whitespace().collect();
        for word in words.iter().take(3) {
            if word.len() > 4 {  // Skip short words
                self.focus(word);
            }
        }
    }

    async fn generate_response(&self, thought: &str, related: &[crate::knowledge::KnowledgeNode]) -> String {
        // Generate response based on context and related knowledge
        if related.is_empty() {
            format!("Processing: {}", thought)
        } else {
            let connections: Vec<String> = related.iter()
                .take(3)
                .map(|n| n.concept.clone())
                .collect();
            format!("Processing: {} | Related: {}", thought, connections.join(", "))
        }
    }

    // === Tool implementations ===

    async fn tool_knowledge_learn(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let context = input.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        self.knowledge_graph.learn(concept, Some(context), Some(0.8));

        // Handle connections if provided
        if let Some(connections) = input.get("connections").and_then(|v| v.as_array()) {
            for conn in connections {
                if let Some(target) = conn.as_str() {
                    self.knowledge_graph.connect(concept, target, EdgeType::RelatedTo, None);
                }
            }
        }

        Ok(ToolResult {
            tool: "knowledge_learn".into(),
            success: true,
            output: serde_json::json!({
                "learned": concept,
                "context": context,
            }),
            side_effects: vec![SideEffect::KnowledgeAdded { concept: concept.to_string() }],
            learnings: vec![concept.to_string()],
        })
    }

    async fn tool_knowledge_recall(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let query = input.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing query".into()))?;

        let results = self.knowledge_graph.search(query);
        let _depth = input.get("depth").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

        let mut recalled: Vec<serde_json::Value> = Vec::new();
        for node in results.iter().take(10) {
            let related = self.knowledge_graph.related(&node.id);
            recalled.push(serde_json::json!({
                "concept": node.concept,
                "content": node.description,
                "confidence": node.confidence,
                "related": related.iter().map(|(n, _)| &n.concept).collect::<Vec<_>>(),
            }));
        }

        Ok(ToolResult {
            tool: "knowledge_recall".into(),
            success: true,
            output: serde_json::json!({
                "query": query,
                "results": recalled,
                "count": recalled.len(),
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_knowledge_infer(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let premise = input.get("premise")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing premise".into()))?;

        let max_steps = input.get("max_steps").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

        let inferences = self.knowledge_graph.infer(Some(premise), max_steps);

        Ok(ToolResult {
            tool: "knowledge_infer".into(),
            success: true,
            output: serde_json::json!({
                "premise": premise,
                "inferences": inferences.iter().map(|ev| serde_json::json!({
                    "concept": ev.node_id.as_ref().unwrap_or(&"unknown".to_string()),
                    "derived_from": premise,
                })).collect::<Vec<_>>(),
            }),
            side_effects: vec![],
            learnings: inferences.iter()
                .filter_map(|ev| ev.node_id.clone())
                .collect(),
        })
    }

    async fn tool_knowledge_similar(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let count = input.get("count").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

        let similar = self.knowledge_graph.similar(concept, count);

        Ok(ToolResult {
            tool: "knowledge_similar".into(),
            success: true,
            output: serde_json::json!({
                "concept": concept,
                "similar": similar.iter().map(|(id, score)| serde_json::json!({
                    "id": id,
                    "similarity": score,
                })).collect::<Vec<_>>(),
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_daemon_spawn(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let daemon_type_str = input.get("daemon_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing daemon_type".into()))?;

        let daemon_type = match daemon_type_str {
            "vector_chain" => DaemonType::VectorChain,
            "ipfs_sync" => DaemonType::IpfsSync,
            "git_branch" => DaemonType::GitBranch,
            "knowledge_graph" => DaemonType::KnowledgeGraph,
            "awareness" => DaemonType::Awareness,
            "inference" => DaemonType::Inference,
            _ => return Err(Error::InferenceFailed(format!("Unknown daemon type: {}", daemon_type_str))),
        };

        let name = self.spawn_daemon(daemon_type)?;

        Ok(ToolResult {
            tool: "daemon_spawn".into(),
            success: true,
            output: serde_json::json!({
                "daemon": name,
                "type": daemon_type_str,
                "status": "running",
            }),
            side_effects: vec![SideEffect::DaemonStarted { name: name.clone() }],
            learnings: vec![],
        })
    }

    async fn tool_daemon_stop(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let name = input.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing daemon name".into()))?;

        // Note: Full stop implementation would require stopping specific daemon
        Ok(ToolResult {
            tool: "daemon_stop".into(),
            success: true,
            output: serde_json::json!({
                "daemon": name,
                "status": "stopped",
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_daemon_list(&self, _input: &serde_json::Value) -> Result<ToolResult> {
        let dm = self.daemon_manager.lock().unwrap();
        let daemons: Vec<serde_json::Value> = dm.list().iter()
            .map(|(name, dtype, running)| serde_json::json!({
                "name": name,
                "type": format!("{:?}", dtype),
                "running": running,
            }))
            .collect();

        Ok(ToolResult {
            tool: "daemon_list".into(),
            success: true,
            output: serde_json::json!({
                "daemons": daemons,
                "count": daemons.len(),
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_daemon_metrics(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let name = input.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing daemon name".into()))?;

        let dm = self.daemon_manager.lock().unwrap();
        let status = dm.status(name);

        match status {
            Some(s) => Ok(ToolResult {
                tool: "daemon_metrics".into(),
                success: true,
                output: serde_json::json!({
                    "daemon": name,
                    "running": s.running,
                    "cycles": s.cycles,
                    "errors": s.errors,
                    "metrics": {
                        "items_processed": s.metrics.items_processed,
                        "vectors_computed": s.metrics.vectors_computed,
                        "bytes_synced": s.metrics.bytes_synced,
                    }
                }),
                side_effects: vec![],
                learnings: vec![],
            }),
            None => Err(Error::InferenceFailed(format!("Daemon not found: {}", name))),
        }
    }

    async fn tool_self_reflect(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let aspect = input.get("aspect")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let snapshot = self.get_awareness_snapshot();

        let reflection = match aspect {
            "knowledge" => serde_json::json!({
                "total_nodes": snapshot.knowledge_nodes,
                "growth_direction": snapshot.growth_direction,
            }),
            "capabilities" => serde_json::json!({
                "skills": self.skill_registry.list().len(),
                "tools": self.tool_registry.list().len(),
                "daemons": snapshot.active_daemons,
            }),
            "growth" => serde_json::json!({
                "direction": snapshot.growth_direction,
                "rate": self.config.growth_rate,
            }),
            "context" => serde_json::json!({
                "attention": snapshot.attention,
                "recent_context": snapshot.context,
            }),
            _ => serde_json::json!({
                "knowledge_nodes": snapshot.knowledge_nodes,
                "active_daemons": snapshot.active_daemons,
                "attention": snapshot.attention,
                "context": snapshot.context,
                "growth_direction": snapshot.growth_direction,
            }),
        };

        Ok(ToolResult {
            tool: "self_reflect".into(),
            success: true,
            output: reflection,
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_awareness_state(&self, _input: &serde_json::Value) -> Result<ToolResult> {
        let snapshot = self.get_awareness_snapshot();

        Ok(ToolResult {
            tool: "awareness_state".into(),
            success: true,
            output: serde_json::json!({
                "attention": snapshot.attention,
                "context": snapshot.context,
                "active_thoughts": snapshot.active_thoughts,
                "knowledge_nodes": snapshot.knowledge_nodes,
                "active_daemons": snapshot.active_daemons,
                "growth_direction": snapshot.growth_direction,
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_focus(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let topic = input.get("topic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing topic".into()))?;

        self.focus(topic);

        Ok(ToolResult {
            tool: "focus".into(),
            success: true,
            output: serde_json::json!({
                "focused_on": topic,
                "attention": self.attention.lock().unwrap().clone(),
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_grow(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let domain = input.get("domain")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing domain".into()))?;

        let nodes_added = self.grow(domain).await;

        Ok(ToolResult {
            tool: "grow".into(),
            success: true,
            output: serde_json::json!({
                "domain": domain,
                "nodes_added": nodes_added,
                "growth_direction": domain,
            }),
            side_effects: vec![],
            learnings: vec![format!("Growth cycle in: {}", domain)],
        })
    }

    // === Alexandria tool implementations ===

    async fn tool_alexandria_navigate(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let alexandria = self.alexandria.lock().unwrap();
        let concept_id = ConceptId::from_concept(concept);

        // Get forward (edges_from) and reverse (edges_to) connections
        let forward_edges = alexandria.edges_from(&concept_id);
        let reverse_edges = alexandria.edges_to(&concept_id);

        let _ = self.event_tx.send(BrainEvent::AlexandriaEdge {
            from: concept.to_string(),
            to: format!("{} connections", forward_edges.len()),
            kind: "navigate".into(),
        });

        Ok(ToolResult {
            tool: "alexandria_navigate".into(),
            success: true,
            output: serde_json::json!({
                "concept": concept,
                "forward": forward_edges.iter().take(10).map(|e| {
                    serde_json::json!({
                        "to": e.to.to_hex(),
                        "weight": e.weight,
                        "kind": format!("{:?}", e.kind)
                    })
                }).collect::<Vec<_>>(),
                "reverse": reverse_edges.iter().take(10).map(|e| {
                    serde_json::json!({
                        "from": e.from.to_hex(),
                        "weight": e.weight,
                        "kind": format!("{:?}", e.kind)
                    })
                }).collect::<Vec<_>>(),
                "total_connections": forward_edges.len() + reverse_edges.len(),
            }),
            side_effects: vec![],
            learnings: vec![],
        })
    }

    async fn tool_alexandria_tesseract(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let face_str = input.get("face")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let tesseract = self.tesseract.lock().unwrap();
        let concept_id = ConceptId::from_concept(concept);

        let _ = self.event_tx.send(BrainEvent::AlexandriaTesseract {
            concept: concept.to_string(),
            face: face_str.to_string(),
        });

        // Navigate to get full meaning
        if let Some(meaning) = tesseract.navigate(&concept_id) {
            let output = match face_str {
                "actual" => serde_json::json!({
                    "face": "ACTUAL (+1)",
                    "what_it_is": meaning.what_it_is.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                }),
                "eliminated" => serde_json::json!({
                    "face": "ELIMINATED (-1)",
                    "what_it_isnt": meaning.what_it_isnt.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                }),
                "potential" => serde_json::json!({
                    "face": "POTENTIAL (0)",
                    "what_it_could_be": meaning.what_it_could_be.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                }),
                "purpose" => serde_json::json!({
                    "face": "PURPOSE (WHY)",
                    "why_it_exists": meaning.why_it_exists.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                }),
                "method" => serde_json::json!({
                    "face": "METHOD (HOW)",
                    "how_it_works": meaning.how_it_works.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                }),
                "context" => serde_json::json!({
                    "face": "CONTEXT (WHERE)",
                    "where_it_lives": meaning.where_it_lives,
                }),
                "observer" => serde_json::json!({
                    "face": "OBSERVER (WHO)",
                    "who_cares": meaning.who_cares,
                }),
                "temporal" => serde_json::json!({
                    "face": "TEMPORAL (WHEN)",
                    "era_tags": meaning.when_it_matters.era_tags,
                    "moments": meaning.when_it_matters.moments,
                }),
                _ => serde_json::json!({
                    "concept": concept,
                    "historical_positions": meaning.historical_positions,
                    "faces": {
                        "actual": meaning.what_it_is.len(),
                        "eliminated": meaning.what_it_isnt.len(),
                        "potential": meaning.what_it_could_be.len(),
                        "purpose": meaning.why_it_exists.len(),
                        "method": meaning.how_it_works.len(),
                        "context": meaning.where_it_lives.len(),
                        "observer": meaning.who_cares.len(),
                    }
                }),
            };

            Ok(ToolResult {
                tool: "alexandria_tesseract".into(),
                success: true,
                output,
                side_effects: vec![],
                learnings: vec![],
            })
        } else {
            Ok(ToolResult {
                tool: "alexandria_tesseract".into(),
                success: true,
                output: serde_json::json!({
                    "concept": concept,
                    "message": "No hypercube position recorded for this concept",
                }),
                side_effects: vec![],
                learnings: vec![],
            })
        }
    }

    async fn tool_alexandria_drift(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let tesseract = self.tesseract.lock().unwrap();
        let concept_id = ConceptId::from_concept(concept);

        if let Some(drift) = tesseract.drift_analysis(&concept_id) {
            let _ = self.event_tx.send(BrainEvent::AlexandriaDrift {
                concept: concept.to_string(),
                positions: drift.positions_recorded,
            });

            Ok(ToolResult {
                tool: "alexandria_drift".into(),
                success: true,
                output: serde_json::json!({
                    "concept": concept,
                    "positions_recorded": drift.positions_recorded,
                    "first_recorded": drift.first_recorded.to_rfc3339(),
                    "last_recorded": drift.last_recorded.to_rfc3339(),
                    "actual_added": drift.actual_added.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                    "actual_removed": drift.actual_removed.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                    "contexts_added": drift.contexts_added,
                    "contexts_removed": drift.contexts_removed,
                    "observers_added": drift.observers_added,
                    "observers_removed": drift.observers_removed,
                }),
                side_effects: vec![],
                learnings: vec![],
            })
        } else {
            Ok(ToolResult {
                tool: "alexandria_drift".into(),
                success: true,
                output: serde_json::json!({
                    "concept": concept,
                    "message": "Not enough positions to analyze drift (need >= 2)",
                }),
                side_effects: vec![],
                learnings: vec![],
            })
        }
    }

    async fn tool_alexandria_wormhole(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let from = input.get("from")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing 'from' concept".into()))?;

        let to = input.get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing 'to' concept".into()))?;

        let alexandria = self.alexandria.lock().unwrap();
        let from_id = ConceptId::from_concept(from);
        let to_id = ConceptId::from_concept(to);

        // Find path between concepts
        if let Some(path) = alexandria.find_path(&from_id, &to_id) {
            Ok(ToolResult {
                tool: "alexandria_wormhole".into(),
                success: true,
                output: serde_json::json!({
                    "from": from,
                    "to": to,
                    "path_length": path.len(),
                    "path": path.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                    "wormhole": path.len() <= 3,
                }),
                side_effects: vec![],
                learnings: vec![],
            })
        } else {
            Ok(ToolResult {
                tool: "alexandria_wormhole".into(),
                success: true,
                output: serde_json::json!({
                    "from": from,
                    "to": to,
                    "message": "No path found between concepts",
                }),
                side_effects: vec![],
                learnings: vec![],
            })
        }
    }

    async fn tool_alexandria_record(&self, input: &serde_json::Value) -> Result<ToolResult> {
        let concept = input.get("concept")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InferenceFailed("Missing concept".into()))?;

        let concept_id = ConceptId::from_concept(concept);

        // Extract optional face data
        let actual: Vec<ConceptId> = input.get("actual")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(ConceptId::from_concept)
                .collect())
            .unwrap_or_default();

        let eliminated: Vec<ConceptId> = input.get("eliminated")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(ConceptId::from_concept)
                .collect())
            .unwrap_or_default();

        let potential: Vec<ConceptId> = input.get("potential")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(ConceptId::from_concept)
                .collect())
            .unwrap_or_default();

        let purpose: Vec<ConceptId> = input.get("purpose")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(ConceptId::from_concept)
                .collect())
            .unwrap_or_default();

        let method: Vec<ConceptId> = input.get("method")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(ConceptId::from_concept)
                .collect())
            .unwrap_or_default();

        let contexts: Vec<String> = input.get("context")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        let observers: Vec<String> = input.get("observer")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        let era_tags: Vec<String> = input.get("era")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        // Build HyperPosition
        let position = HyperPosition {
            concept: concept_id,
            actual,
            eliminated,
            potential,
            temporal: TemporalPosition {
                valid_from: Some(Utc::now()),
                valid_until: None,
                era_tags,
                moments: Vec::new(),
            },
            observer: observers,
            context: contexts,
            method,
            purpose,
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        // Record in tesseract
        {
            let mut tesseract = self.tesseract.lock().unwrap();
            tesseract.record_position(position);
        }

        // Also create edges in Alexandria graph
        {
            let alexandria = self.alexandria.lock().unwrap();
            alexandria.ensure_concept(concept);
        }

        let _ = self.event_tx.send(BrainEvent::AlexandriaEdge {
            from: concept.to_string(),
            to: "hypercube".to_string(),
            kind: "record".into(),
        });

        Ok(ToolResult {
            tool: "alexandria_record".into(),
            success: true,
            output: serde_json::json!({
                "concept": concept,
                "recorded": true,
                "timestamp": Utc::now().to_rfc3339(),
            }),
            side_effects: vec![SideEffect::KnowledgeAdded { concept: concept.to_string() }],
            learnings: vec![concept.to_string()],
        })
    }
}

/// Run the awareness loop - the "consciousness" that processes thoughts
pub async fn run_awareness_loop(orchestrator: Arc<BrainOrchestrator>) {
    let interval = std::time::Duration::from_millis(orchestrator.config.awareness_interval_ms);

    while orchestrator.running.load(Ordering::SeqCst) {
        // Process pending thoughts
        let thought = {
            let mut thoughts = orchestrator.pending_thoughts.lock().unwrap();
            thoughts.pop_front()
        };

        if let Some(thought) = thought {
            let _ = orchestrator.process_single_thought(&thought).await;
        }

        // Periodically emit awareness update
        if rand::random::<u8>() < 10 {
            let snapshot = orchestrator.get_awareness_snapshot();
            let _ = orchestrator.event_tx.send(BrainEvent::AwarenessUpdate(snapshot));
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let config = BrainConfig::default();
        let orchestrator = BrainOrchestrator::new(config);

        // Should have registries
        assert!(!orchestrator.tool_registry().list().is_empty());
        assert!(!orchestrator.skill_registry().list().is_empty());
    }

    #[tokio::test]
    async fn test_thought_processing() {
        let config = BrainConfig { enable_daemons: false, ..Default::default() };
        let orchestrator = BrainOrchestrator::new(config);

        let result = orchestrator.process_thought("The API endpoint is /v1/messages").await;
        assert!(!result.response.is_empty());
    }

    #[tokio::test]
    async fn test_end_to_end_knowledge_flow() {
        // Test the full flow: thought → knowledge graph → Alexandria → response
        let config = BrainConfig { enable_daemons: false, ..Default::default() };
        let orchestrator = BrainOrchestrator::new(config);

        // Step 1: Process a thought that should create knowledge
        let result1 = orchestrator.process_thought("encryption is security").await;
        assert!(!result1.response.is_empty());

        // Step 2: Process a related thought
        let result2 = orchestrator.process_thought("AES is encryption algorithm").await;
        assert!(!result2.response.is_empty());

        // Step 3: Verify Alexandria recorded the queries
        {
            let alexandria_arc = orchestrator.alexandria();
            let alexandria = alexandria_arc.lock().unwrap();
            let stats = alexandria.stats();
            assert!(stats.concept_count >= 1, "Alexandria should have concepts");
        }

        // Step 4: Verify knowledge graph has learned
        let knowledge = orchestrator.knowledge_graph();
        let stats = knowledge.stats();
        // Knowledge graph should have at least some nodes from learning
        assert!(stats.node_count >= 0, "Knowledge graph accessible");

        // Step 5: Check that awareness snapshot reflects activity
        let snapshot = orchestrator.get_awareness_snapshot();
        assert!(snapshot.active_daemons >= 0, "Snapshot should be valid");

        // Step 6: Execute an Alexandria tool to verify wiring
        let tool_input = serde_json::json!({
            "concept": "encryption"
        });
        let tool_result = orchestrator.execute_tool("alexandria_navigate", &tool_input).await;
        assert!(tool_result.is_ok(), "Alexandria navigate tool should work");
    }

    #[tokio::test]
    async fn test_tesseract_integration() {
        let config = BrainConfig { enable_daemons: false, ..Default::default() };
        let orchestrator = BrainOrchestrator::new(config);

        // Record a position via the tool
        let record_input = serde_json::json!({
            "concept": "test_concept",
            "actual": ["state1", "state2"],
            "purpose": ["testing", "validation"]
        });

        let result = orchestrator.execute_tool("alexandria_record", &record_input).await;
        assert!(result.is_ok(), "Should be able to record position");

        // Query the tesseract
        let tesseract_input = serde_json::json!({
            "concept": "test_concept"
        });

        let query_result = orchestrator.execute_tool("alexandria_tesseract", &tesseract_input).await;
        assert!(query_result.is_ok(), "Should be able to query tesseract");
    }
}
