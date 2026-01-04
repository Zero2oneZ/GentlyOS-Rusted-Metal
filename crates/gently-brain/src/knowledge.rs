//! Recursive Knowledge Graph
//!
//! A self-growing, decentralized knowledge structure.
//! Nodes are concepts, edges are relationships.
//! Syncs to IPFS for persistence and distribution.
//! Persists to SQLite for local durability.

use crate::{Result, Error};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A node in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    pub id: String,
    pub concept: String,
    pub description: String,
    pub node_type: NodeType,
    pub vector: Option<Vec<f32>>,  // Embedding
    pub confidence: f32,           // How sure we are about this
    pub source: Option<String>,    // Where this came from
    pub created_at: i64,
    pub accessed_count: u32,
    pub ipfs_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    Concept,     // Abstract idea
    Fact,        // Concrete fact
    Procedure,   // How to do something
    Entity,      // Named thing (person, tool, etc.)
    Relation,    // A relationship type
    Context,     // Contextual knowledge
    Skill,       // A capability
    Experience,  // Something we learned from doing
}

/// An edge connecting two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    pub from: String,
    pub to: String,
    pub edge_type: EdgeType,
    pub weight: f32,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum EdgeType {
    IsA,         // A is a B
    HasA,        // A has a B
    PartOf,      // A is part of B
    Causes,      // A causes B
    Enables,     // A enables B
    Requires,    // A requires B
    RelatedTo,   // A is related to B
    Contradicts, // A contradicts B
    Supports,    // A supports B
    LeadsTo,     // A leads to B
    DerivedFrom, // A is derived from B
    UsedIn,      // A is used in B
}

/// The knowledge graph
#[derive(Clone)]
pub struct KnowledgeGraph {
    nodes: Arc<Mutex<HashMap<String, KnowledgeNode>>>,
    edges: Arc<Mutex<Vec<KnowledgeEdge>>>,
    index: Arc<Mutex<GraphIndex>>,
    growth_log: Arc<Mutex<Vec<GrowthEvent>>>,
}

/// Index for fast lookups
#[derive(Default, Clone)]
struct GraphIndex {
    by_type: HashMap<NodeType, HashSet<String>>,
    by_concept: HashMap<String, String>,  // Concept -> node ID
    outgoing: HashMap<String, Vec<usize>>, // Node ID -> edge indices
    incoming: HashMap<String, Vec<usize>>, // Node ID -> edge indices
}

/// Record of how the graph grows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowthEvent {
    pub timestamp: i64,
    pub event_type: GrowthType,
    pub node_id: Option<String>,
    pub edge_index: Option<usize>,
    pub trigger: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum GrowthType {
    NodeAdded,
    NodeUpdated,
    EdgeAdded,
    EdgeStrengthened,
    NodeMerged,
    SubgraphCreated,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            edges: Arc::new(Mutex::new(Vec::new())),
            index: Arc::new(Mutex::new(GraphIndex::default())),
            growth_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a new concept to the graph
    pub fn add_concept(&self, concept: &str, description: &str, node_type: NodeType) -> String {
        let id = format!("node_{}", uuid::Uuid::new_v4().to_string()[..8].to_string());

        let node = KnowledgeNode {
            id: id.clone(),
            concept: concept.to_string(),
            description: description.to_string(),
            node_type,
            vector: None,
            confidence: 0.5,
            source: None,
            created_at: chrono::Utc::now().timestamp(),
            accessed_count: 0,
            ipfs_cid: None,
        };

        // Add to nodes
        {
            let mut nodes = self.nodes.lock().unwrap();
            nodes.insert(id.clone(), node);
        }

        // Update index
        {
            let mut index = self.index.lock().unwrap();
            index.by_type.entry(node_type).or_default().insert(id.clone());
            index.by_concept.insert(concept.to_lowercase(), id.clone());
        }

        // Log growth
        self.log_growth(GrowthType::NodeAdded, Some(id.clone()), None, "add_concept");

        id
    }

    /// Connect two nodes (weight defaults to 1.0)
    pub fn connect(&self, from: &str, to: &str, edge_type: EdgeType, weight: Option<f32>) {
        let edge = KnowledgeEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type,
            weight: weight.unwrap_or(1.0),
            context: None,
        };

        let edge_idx = {
            let mut edges = self.edges.lock().unwrap();
            let idx = edges.len();
            edges.push(edge);
            idx
        };

        // Update index
        {
            let mut index = self.index.lock().unwrap();
            index.outgoing.entry(from.to_string()).or_default().push(edge_idx);
            index.incoming.entry(to.to_string()).or_default().push(edge_idx);
        }

        self.log_growth(GrowthType::EdgeAdded, None, Some(edge_idx), "connect");
    }

    /// Find a node by concept name
    pub fn find(&self, concept: &str) -> Option<KnowledgeNode> {
        let id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&concept.to_lowercase()).cloned()
        };

        if let Some(id) = id {
            let nodes = self.nodes.lock().unwrap();
            nodes.get(&id).cloned()
        } else {
            None
        }
    }

    /// Search for nodes matching a query (returns Vec, unlike find which returns Option)
    /// Use "*" to get all nodes
    pub fn search(&self, query: &str) -> Vec<KnowledgeNode> {
        let nodes = self.nodes.lock().unwrap();

        if query == "*" {
            return nodes.values().cloned().collect();
        }

        let query_lower = query.to_lowercase();
        nodes.values()
            .filter(|n| {
                n.concept.to_lowercase().contains(&query_lower) ||
                n.description.to_lowercase().contains(&query_lower)
            })
            .cloned()
            .collect()
    }

    /// Get a node and increment access count
    pub fn access(&self, id: &str) -> Option<KnowledgeNode> {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            node.accessed_count += 1;
            Some(node.clone())
        } else {
            None
        }
    }

    /// Get related nodes (connected by edges)
    pub fn related(&self, id: &str) -> Vec<(KnowledgeNode, EdgeType)> {
        let edges = self.edges.lock().unwrap();
        let index = self.index.lock().unwrap();
        let nodes = self.nodes.lock().unwrap();

        let mut related = Vec::new();

        // Outgoing edges
        if let Some(indices) = index.outgoing.get(id) {
            for &idx in indices {
                if let Some(edge) = edges.get(idx) {
                    if let Some(node) = nodes.get(&edge.to) {
                        related.push((node.clone(), edge.edge_type));
                    }
                }
            }
        }

        // Incoming edges
        if let Some(indices) = index.incoming.get(id) {
            for &idx in indices {
                if let Some(edge) = edges.get(idx) {
                    if let Some(node) = nodes.get(&edge.from) {
                        related.push((node.clone(), edge.edge_type));
                    }
                }
            }
        }

        related
    }

    /// Find path between two concepts using BFS
    pub fn find_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let from_id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&from.to_lowercase()).cloned()
        }?;

        let to_id = {
            let index = self.index.lock().unwrap();
            index.by_concept.get(&to.to_lowercase()).cloned()
        }?;

        // BFS
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(from_id.clone());
        visited.insert(from_id.clone());

        while let Some(current) = queue.pop_front() {
            if current == to_id {
                // Reconstruct path
                let mut path = vec![current.clone()];
                let mut curr = current;
                while let Some(p) = parent.get(&curr) {
                    path.push(p.clone());
                    curr = p.clone();
                }
                path.reverse();
                return Some(path);
            }

            for (related, _) in self.related(&current) {
                if !visited.contains(&related.id) {
                    visited.insert(related.id.clone());
                    parent.insert(related.id.clone(), current.clone());
                    queue.push_back(related.id);
                }
            }
        }

        None
    }

    /// Learn from text - extract concepts and relationships
    /// confidence defaults to 1.0 if not provided
    pub fn learn(&self, text: &str, source: Option<&str>, confidence: Option<f32>) -> Vec<String> {
        let conf = confidence.unwrap_or(1.0);
        let mut added = Vec::new();

        // Simple extraction (in real impl, use NLP)
        let words: Vec<&str> = text.split_whitespace().collect();

        for window in words.windows(3) {
            // Look for "X is Y" patterns
            if window.len() == 3 && window[1].to_lowercase() == "is" {
                let from = self.ensure_concept(window[0], source);
                let to = self.ensure_concept(window[2], source);
                self.connect(&from, &to, EdgeType::IsA, Some(conf * 0.5));
                added.push(from);
                added.push(to);
            }

            // Look for "X has Y" patterns
            if window.len() == 3 && window[1].to_lowercase() == "has" {
                let from = self.ensure_concept(window[0], source);
                let to = self.ensure_concept(window[2], source);
                self.connect(&from, &to, EdgeType::HasA, Some(conf * 0.5));
                added.push(from);
                added.push(to);
            }
        }

        added
    }

    /// Ensure a concept exists, create if not
    fn ensure_concept(&self, concept: &str, source: Option<&str>) -> String {
        if let Some(node) = self.find(concept) {
            node.id
        } else {
            let id = self.add_concept(concept, "", NodeType::Concept);
            if let Some(src) = source {
                let mut nodes = self.nodes.lock().unwrap();
                if let Some(node) = nodes.get_mut(&id) {
                    node.source = Some(src.to_string());
                }
            }
            id
        }
    }

    /// Grow the graph by inference (find implicit connections)
    /// premise: Optional starting concept to focus inference on
    /// max_depth: Maximum depth of transitive inference (defaults to 3)
    pub fn infer(&self, premise: Option<&str>, max_depth: usize) -> Vec<GrowthEvent> {
        let mut inferences = Vec::new();
        let depth = if max_depth == 0 { 3 } else { max_depth };

        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();

        // Filter edges if premise is provided
        let relevant_edges: Vec<_> = if let Some(p) = premise {
            let p_lower = p.to_lowercase();
            edges.iter()
                .filter(|e| e.from.to_lowercase().contains(&p_lower) ||
                           e.to.to_lowercase().contains(&p_lower))
                .collect()
        } else {
            edges.iter().collect()
        };

        // Transitive inference: if A->B and B->C, then A might relate to C
        for edge_ab in relevant_edges.iter().take(depth * 10) {
            for edge_bc in edges.iter() {
                if edge_ab.to == edge_bc.from && edge_ab.from != edge_bc.to {
                    // Check if A->C already exists
                    let exists = edges.iter().any(|e| e.from == edge_ab.from && e.to == edge_bc.to);

                    if !exists {
                        // This is a potential new edge
                        inferences.push(GrowthEvent {
                            timestamp: chrono::Utc::now().timestamp(),
                            event_type: GrowthType::EdgeAdded,
                            node_id: Some(edge_bc.to.clone()),
                            edge_index: None,
                            trigger: format!("transitive inference: {} -> {} -> {}",
                                edge_ab.from, edge_ab.to, edge_bc.to),
                        });
                    }
                }
            }
        }

        drop(nodes);
        drop(edges);

        inferences
    }

    /// Set vector embedding for a node
    pub fn set_vector(&self, id: &str, vector: Vec<f32>) {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(id) {
            node.vector = Some(vector);
        }
    }

    /// Find similar nodes by vector similarity
    pub fn similar(&self, id: &str, top_k: usize) -> Vec<(String, f32)> {
        let nodes = self.nodes.lock().unwrap();

        let target_vector = match nodes.get(id) {
            Some(node) => match &node.vector {
                Some(v) => v.clone(),
                None => return vec![],
            },
            None => return vec![],
        };

        let mut similarities: Vec<(String, f32)> = nodes.iter()
            .filter(|(nid, _)| *nid != id)
            .filter_map(|(nid, node)| {
                node.vector.as_ref().map(|v| {
                    let sim = cosine_similarity(&target_vector, v);
                    (nid.clone(), sim)
                })
            })
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(top_k);
        similarities
    }

    /// Export graph for IPFS
    pub fn export(&self) -> Vec<u8> {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();

        let export = GraphExport {
            nodes: nodes.values().cloned().collect(),
            edges: edges.clone(),
            exported_at: chrono::Utc::now().timestamp(),
        };

        serde_json::to_vec(&export).unwrap_or_default()
    }

    /// Import graph from IPFS
    pub fn import(&self, data: &[u8]) -> Result<()> {
        let export: GraphExport = serde_json::from_slice(data)
            .map_err(|e| Error::InferenceFailed(e.to_string()))?;

        let mut nodes = self.nodes.lock().unwrap();
        let mut edges = self.edges.lock().unwrap();
        let mut index = self.index.lock().unwrap();

        for node in export.nodes {
            index.by_type.entry(node.node_type).or_default().insert(node.id.clone());
            index.by_concept.insert(node.concept.to_lowercase(), node.id.clone());
            nodes.insert(node.id.clone(), node);
        }

        let base_idx = edges.len();
        for (i, edge) in export.edges.iter().enumerate() {
            index.outgoing.entry(edge.from.clone()).or_default().push(base_idx + i);
            index.incoming.entry(edge.to.clone()).or_default().push(base_idx + i);
        }
        edges.extend(export.edges);

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> GraphStats {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();
        let growth_log = self.growth_log.lock().unwrap();

        GraphStats {
            node_count: nodes.len(),
            edge_count: edges.len(),
            growth_events: growth_log.len(),
            types: self.type_distribution(),
        }
    }

    fn type_distribution(&self) -> HashMap<String, usize> {
        let index = self.index.lock().unwrap();
        index.by_type.iter()
            .map(|(t, ids)| (format!("{:?}", t), ids.len()))
            .collect()
    }

    fn log_growth(&self, event_type: GrowthType, node_id: Option<String>, edge_index: Option<usize>, trigger: &str) {
        let mut log = self.growth_log.lock().unwrap();
        log.push(GrowthEvent {
            timestamp: chrono::Utc::now().timestamp(),
            event_type,
            node_id,
            edge_index,
            trigger: trigger.to_string(),
        });
    }

    // ========== SQLite Persistence ==========

    /// Get default database path (~/.gently/brain/knowledge.db)
    pub fn default_db_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gently")
            .join("brain")
            .join("knowledge.db")
    }

    /// Initialize the SQLite database (creates tables if needed)
    fn init_db(conn: &Connection) -> Result<()> {
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                concept TEXT NOT NULL,
                description TEXT,
                node_type TEXT NOT NULL,
                vector BLOB,
                confidence REAL DEFAULT 0.5,
                source TEXT,
                created_at INTEGER NOT NULL,
                accessed_count INTEGER DEFAULT 0,
                ipfs_cid TEXT
            );

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                context TEXT,
                FOREIGN KEY (from_id) REFERENCES nodes(id),
                FOREIGN KEY (to_id) REFERENCES nodes(id)
            );

            CREATE INDEX IF NOT EXISTS idx_nodes_concept ON nodes(concept);
            CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id);
            CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_id);
        "#).map_err(|e| Error::InferenceFailed(format!("Failed to init DB: {}", e)))?;

        Ok(())
    }

    /// Save the graph to SQLite
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| Error::InferenceFailed(format!("Failed to open DB: {}", e)))?;

        Self::init_db(&conn)?;

        // Begin transaction
        conn.execute("BEGIN TRANSACTION", [])
            .map_err(|e| Error::InferenceFailed(format!("Failed to begin transaction: {}", e)))?;

        // Clear existing data
        conn.execute("DELETE FROM edges", [])
            .map_err(|e| Error::InferenceFailed(format!("Failed to clear edges: {}", e)))?;
        conn.execute("DELETE FROM nodes", [])
            .map_err(|e| Error::InferenceFailed(format!("Failed to clear nodes: {}", e)))?;

        // Save nodes
        let nodes = self.nodes.lock().unwrap();
        for node in nodes.values() {
            let vector_blob: Option<Vec<u8>> = node.vector.as_ref().map(|v| {
                v.iter().flat_map(|f| f.to_le_bytes()).collect()
            });

            conn.execute(
                r#"INSERT INTO nodes (id, concept, description, node_type, vector, confidence, source, created_at, accessed_count, ipfs_cid)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
                params![
                    node.id,
                    node.concept,
                    node.description,
                    format!("{:?}", node.node_type),
                    vector_blob,
                    node.confidence,
                    node.source,
                    node.created_at,
                    node.accessed_count,
                    node.ipfs_cid,
                ],
            ).map_err(|e| Error::InferenceFailed(format!("Failed to insert node: {}", e)))?;
        }
        drop(nodes);

        // Save edges
        let edges = self.edges.lock().unwrap();
        for edge in edges.iter() {
            conn.execute(
                r#"INSERT INTO edges (from_id, to_id, edge_type, weight, context)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
                params![
                    edge.from,
                    edge.to,
                    format!("{:?}", edge.edge_type),
                    edge.weight,
                    edge.context,
                ],
            ).map_err(|e| Error::InferenceFailed(format!("Failed to insert edge: {}", e)))?;
        }
        drop(edges);

        // Commit transaction
        conn.execute("COMMIT", [])
            .map_err(|e| Error::InferenceFailed(format!("Failed to commit: {}", e)))?;

        tracing::info!("Saved knowledge graph to {}", path.display());
        Ok(())
    }

    /// Save to default path
    pub fn save_default(&self) -> Result<()> {
        self.save(&Self::default_db_path())
    }

    /// Load the graph from SQLite
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::ModelNotFound(format!("Database not found: {}", path.display())));
        }

        let conn = Connection::open(path)
            .map_err(|e| Error::InferenceFailed(format!("Failed to open DB: {}", e)))?;

        let graph = Self::new();

        // Load nodes
        {
            let mut stmt = conn.prepare(
                "SELECT id, concept, description, node_type, vector, confidence, source, created_at, accessed_count, ipfs_cid FROM nodes"
            ).map_err(|e| Error::InferenceFailed(format!("Failed to prepare node query: {}", e)))?;

            let mut rows = stmt.query([])
                .map_err(|e| Error::InferenceFailed(format!("Failed to query nodes: {}", e)))?;

            let mut nodes = graph.nodes.lock().unwrap();
            let mut index = graph.index.lock().unwrap();

            while let Some(row) = rows.next()
                .map_err(|e| Error::InferenceFailed(format!("Failed to fetch row: {}", e)))?
            {
                let id: String = row.get(0).unwrap_or_default();
                let concept: String = row.get(1).unwrap_or_default();
                let description: String = row.get(2).unwrap_or_default();
                let node_type_str: String = row.get(3).unwrap_or_default();
                let vector_blob: Option<Vec<u8>> = row.get(4).ok();
                let confidence: f32 = row.get(5).unwrap_or(0.5);
                let source: Option<String> = row.get(6).ok();
                let created_at: i64 = row.get(7).unwrap_or(0);
                let accessed_count: u32 = row.get(8).unwrap_or(0);
                let ipfs_cid: Option<String> = row.get(9).ok();

                let node_type = parse_node_type(&node_type_str);
                let vector = vector_blob.map(|blob| {
                    blob.chunks(4)
                        .map(|chunk| {
                            let arr: [u8; 4] = chunk.try_into().unwrap_or([0; 4]);
                            f32::from_le_bytes(arr)
                        })
                        .collect()
                });

                let node = KnowledgeNode {
                    id: id.clone(),
                    concept: concept.clone(),
                    description,
                    node_type,
                    vector,
                    confidence,
                    source,
                    created_at,
                    accessed_count,
                    ipfs_cid,
                };

                index.by_type.entry(node_type).or_default().insert(id.clone());
                index.by_concept.insert(concept.to_lowercase(), id.clone());
                nodes.insert(id, node);
            }
        }

        // Load edges
        {
            let mut stmt = conn.prepare(
                "SELECT from_id, to_id, edge_type, weight, context FROM edges"
            ).map_err(|e| Error::InferenceFailed(format!("Failed to prepare edge query: {}", e)))?;

            let mut rows = stmt.query([])
                .map_err(|e| Error::InferenceFailed(format!("Failed to query edges: {}", e)))?;

            let mut edges = graph.edges.lock().unwrap();
            let mut index = graph.index.lock().unwrap();

            while let Some(row) = rows.next()
                .map_err(|e| Error::InferenceFailed(format!("Failed to fetch row: {}", e)))?
            {
                let from: String = row.get(0).unwrap_or_default();
                let to: String = row.get(1).unwrap_or_default();
                let edge_type_str: String = row.get(2).unwrap_or_default();
                let weight: f32 = row.get(3).unwrap_or(1.0);
                let context: Option<String> = row.get(4).ok();

                let edge_type = parse_edge_type(&edge_type_str);
                let edge_idx = edges.len();

                let edge = KnowledgeEdge {
                    from: from.clone(),
                    to: to.clone(),
                    edge_type,
                    weight,
                    context,
                };

                index.outgoing.entry(from).or_default().push(edge_idx);
                index.incoming.entry(to).or_default().push(edge_idx);
                edges.push(edge);
            }
        }

        tracing::info!("Loaded knowledge graph from {}", path.display());
        Ok(graph)
    }

    /// Load from default path
    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_db_path())
    }

    /// Load from file or create new
    pub fn load_or_create(path: &Path) -> Self {
        match Self::load(path) {
            Ok(graph) => graph,
            Err(e) => {
                tracing::info!("Creating new knowledge graph ({})", e);
                Self::new()
            }
        }
    }

    /// Load from default path or create new
    pub fn load_or_create_default() -> Self {
        Self::load_or_create(&Self::default_db_path())
    }

    /// Check if database exists
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }
}

/// Parse node type from string
fn parse_node_type(s: &str) -> NodeType {
    match s {
        "Concept" => NodeType::Concept,
        "Fact" => NodeType::Fact,
        "Procedure" => NodeType::Procedure,
        "Entity" => NodeType::Entity,
        "Relation" => NodeType::Relation,
        "Context" => NodeType::Context,
        "Skill" => NodeType::Skill,
        "Experience" => NodeType::Experience,
        _ => NodeType::Concept,
    }
}

/// Parse edge type from string
fn parse_edge_type(s: &str) -> EdgeType {
    match s {
        "IsA" => EdgeType::IsA,
        "HasA" => EdgeType::HasA,
        "PartOf" => EdgeType::PartOf,
        "Causes" => EdgeType::Causes,
        "Enables" => EdgeType::Enables,
        "Requires" => EdgeType::Requires,
        "RelatedTo" => EdgeType::RelatedTo,
        "Contradicts" => EdgeType::Contradicts,
        "Supports" => EdgeType::Supports,
        "LeadsTo" => EdgeType::LeadsTo,
        "DerivedFrom" => EdgeType::DerivedFrom,
        "UsedIn" => EdgeType::UsedIn,
        _ => EdgeType::RelatedTo,
    }
}

#[derive(Serialize, Deserialize)]
struct GraphExport {
    nodes: Vec<KnowledgeNode>,
    edges: Vec<KnowledgeEdge>,
    exported_at: i64,
}

#[derive(Debug)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub growth_events: usize,
    pub types: HashMap<String, usize>,
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knowledge_graph() {
        let graph = KnowledgeGraph::new();

        let cipher = graph.add_concept("cipher", "Encryption algorithm", NodeType::Concept);
        let aes = graph.add_concept("AES", "Advanced Encryption Standard", NodeType::Concept);

        graph.connect(&aes, &cipher, EdgeType::IsA, Some(1.0));

        let related = graph.related(&aes);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].0.concept, "cipher");
    }

    #[test]
    fn test_learning() {
        let graph = KnowledgeGraph::new();
        graph.learn("AES is cipher", Some("test"), None);

        assert!(graph.find("AES").is_some());
        assert!(graph.find("cipher").is_some());
    }

    #[test]
    fn test_sqlite_persistence() {
        use std::path::PathBuf;

        // Use temp file for test
        let test_path = PathBuf::from("/tmp/gently_brain_test.db");

        // Clean up any previous test
        let _ = std::fs::remove_file(&test_path);

        // Create graph with data
        let graph = KnowledgeGraph::new();
        let rust_id = graph.add_concept("Rust", "Systems programming language", NodeType::Concept);
        let memory_id = graph.add_concept("Memory Safety", "Prevents memory bugs", NodeType::Concept);
        graph.connect(&rust_id, &memory_id, EdgeType::Enables, Some(0.9));

        // Set a vector on one node
        graph.set_vector(&rust_id, vec![0.1, 0.2, 0.3, 0.4]);

        // Verify data before save
        let stats_before = graph.stats();
        assert_eq!(stats_before.node_count, 2);
        assert_eq!(stats_before.edge_count, 1);

        // Save to SQLite
        graph.save(&test_path).expect("Failed to save");
        assert!(test_path.exists());

        // Load from SQLite
        let loaded = KnowledgeGraph::load(&test_path).expect("Failed to load");

        // Verify data after load
        let stats_after = loaded.stats();
        assert_eq!(stats_after.node_count, 2);
        assert_eq!(stats_after.edge_count, 1);

        // Verify specific nodes
        let rust_node = loaded.find("Rust").expect("Rust node not found");
        assert_eq!(rust_node.description, "Systems programming language");
        assert!(rust_node.vector.is_some());
        assert_eq!(rust_node.vector.unwrap().len(), 4);

        let memory_node = loaded.find("Memory Safety").expect("Memory Safety node not found");
        assert_eq!(memory_node.description, "Prevents memory bugs");

        // Verify edges (via related)
        let related = loaded.related(&rust_node.id);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].1, EdgeType::Enables);

        // Clean up
        let _ = std::fs::remove_file(&test_path);
    }

    #[test]
    fn test_load_or_create() {
        use std::path::PathBuf;

        let test_path = PathBuf::from("/tmp/gently_brain_nonexistent.db");
        let _ = std::fs::remove_file(&test_path);

        // Should create new graph if doesn't exist
        let graph = KnowledgeGraph::load_or_create(&test_path);
        assert_eq!(graph.stats().node_count, 0);

        // Add data and save
        graph.add_concept("Test", "Test node", NodeType::Fact);
        graph.save(&test_path).expect("Failed to save");

        // Now load_or_create should load existing
        let loaded = KnowledgeGraph::load_or_create(&test_path);
        assert_eq!(loaded.stats().node_count, 1);

        // Clean up
        let _ = std::fs::remove_file(&test_path);
    }
}
