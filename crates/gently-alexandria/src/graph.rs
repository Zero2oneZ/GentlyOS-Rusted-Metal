//! Alexandria Graph - The distributed knowledge structure
//!
//! ```text
//! DAY 1:
//! User queries: "encryption"
//! Map: encryption ─── [similar: crypto, cipher]
//!      1 node, 2 edges
//!
//! DAY 30:
//! 10,000 queries
//! Map: encryption ─┬─ similar: [crypto, cipher, RSA]
//!                  ├─ orthogonal: [timestamp, children, wallet]
//!                  ├─ inverse: [security, protect, hide]
//!                  └─ reroutes: [math → prime → RSA → encryption]
//!
//!      847 nodes, 12,453 edges
//!      BUILT FROM USAGE
//! ```

use crate::concept::{Concept, ConceptId};
use crate::edge::{AlexandriaEdge, EdgeKind, EdgeUpdate};
use crate::node::NodeFingerprint;
use crate::sync::GraphDelta;
use crate::{AlexandriaConfig, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// The Alexandria knowledge graph
#[derive(Clone)]
pub struct AlexandriaGraph {
    /// Our node's fingerprint
    local_node: NodeFingerprint,

    /// Configuration
    config: AlexandriaConfig,

    /// All concepts
    concepts: Arc<RwLock<HashMap<ConceptId, Concept>>>,

    /// All edges (keyed by ordered pair of concept IDs)
    edges: Arc<RwLock<HashMap<(ConceptId, ConceptId), AlexandriaEdge>>>,

    /// Index: concept -> outgoing edges
    outgoing: Arc<RwLock<HashMap<ConceptId, HashSet<ConceptId>>>>,

    /// Index: concept -> incoming edges
    incoming: Arc<RwLock<HashMap<ConceptId, HashSet<ConceptId>>>>,

    /// Current session for tracking user paths
    current_session: Arc<RwLock<Vec<ConceptId>>>,

    /// Pending updates to publish
    pending_updates: Arc<RwLock<Vec<EdgeUpdate>>>,

    /// Sequence number for deltas
    sequence: Arc<RwLock<u64>>,
}

impl AlexandriaGraph {
    /// Create new graph
    pub fn new(local_node: NodeFingerprint, config: AlexandriaConfig) -> Self {
        Self {
            local_node,
            config,
            concepts: Arc::new(RwLock::new(HashMap::new())),
            edges: Arc::new(RwLock::new(HashMap::new())),
            outgoing: Arc::new(RwLock::new(HashMap::new())),
            incoming: Arc::new(RwLock::new(HashMap::new())),
            current_session: Arc::new(RwLock::new(Vec::new())),
            pending_updates: Arc::new(RwLock::new(Vec::new())),
            sequence: Arc::new(RwLock::new(0)),
        }
    }

    /// Create with default config
    pub fn with_defaults(local_node: NodeFingerprint) -> Self {
        Self::new(local_node, AlexandriaConfig::default())
    }

    // ========== Concept Operations ==========

    /// Get or create a concept
    pub fn ensure_concept(&self, text: &str) -> ConceptId {
        let id = ConceptId::from_concept(text);

        let mut concepts = self.concepts.write().unwrap();
        concepts.entry(id).or_insert_with(|| Concept::new(text));

        id
    }

    /// Get concept by ID
    pub fn get_concept(&self, id: &ConceptId) -> Option<Concept> {
        let concepts = self.concepts.read().unwrap();
        concepts.get(id).cloned()
    }

    /// Set embedding for a concept
    pub fn set_embedding(&self, id: &ConceptId, embedding: Vec<f32>) {
        let mut concepts = self.concepts.write().unwrap();
        if let Some(concept) = concepts.get_mut(id) {
            concept.embedding = Some(embedding);
        }
    }

    /// Get all concepts
    pub fn all_concepts(&self) -> Vec<Concept> {
        let concepts = self.concepts.read().unwrap();
        concepts.values().cloned().collect()
    }

    /// Concept count
    pub fn concept_count(&self) -> usize {
        let concepts = self.concepts.read().unwrap();
        concepts.len()
    }

    // ========== Edge Operations ==========

    /// Add or update an edge
    pub fn add_edge(&self, from: ConceptId, to: ConceptId, kind: EdgeKind) {
        // Ensure concepts exist
        {
            let mut concepts = self.concepts.write().unwrap();
            concepts.entry(from).or_insert_with(|| {
                let mut c = Concept::new("");
                c.id = from;
                c
            });
            concepts.entry(to).or_insert_with(|| {
                let mut c = Concept::new("");
                c.id = to;
                c
            });
        }

        // Create edge key (ordered)
        let key = if from.0 < to.0 { (from, to) } else { (to, from) };

        let mut edges = self.edges.write().unwrap();
        let mut outgoing = self.outgoing.write().unwrap();
        let mut incoming = self.incoming.write().unwrap();

        edges
            .entry(key)
            .and_modify(|e| {
                e.use_edge();
                if !e.source_nodes.contains(&self.local_node) {
                    e.source_nodes.push(self.local_node);
                }
            })
            .or_insert_with(|| {
                AlexandriaEdge::new(from, to, kind.clone())
                    .with_weight(kind.base_weight())
                    .with_source(self.local_node)
            });

        // Update indices
        outgoing.entry(from).or_default().insert(to);
        incoming.entry(to).or_default().insert(from);

        // Queue update for sync
        drop(edges);
        drop(outgoing);
        drop(incoming);

        let mut pending = self.pending_updates.write().unwrap();
        pending.push(EdgeUpdate::WeightIncrement {
            from,
            to,
            delta: kind.base_weight() * 0.1,
            source_node: self.local_node,
        });
    }

    /// Get edge between two concepts
    pub fn get_edge(&self, from: &ConceptId, to: &ConceptId) -> Option<AlexandriaEdge> {
        let key = if from.0 < to.0 {
            (*from, *to)
        } else {
            (*to, *from)
        };
        let edges = self.edges.read().unwrap();
        edges.get(&key).cloned()
    }

    /// Get all edges from a concept
    pub fn edges_from(&self, concept: &ConceptId) -> Vec<AlexandriaEdge> {
        let outgoing = self.outgoing.read().unwrap();
        let edges = self.edges.read().unwrap();

        outgoing
            .get(concept)
            .map(|targets| {
                targets
                    .iter()
                    .filter_map(|to| {
                        let key = if concept.0 < to.0 {
                            (*concept, *to)
                        } else {
                            (*to, *concept)
                        };
                        edges.get(&key).cloned()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all edges to a concept
    pub fn edges_to(&self, concept: &ConceptId) -> Vec<AlexandriaEdge> {
        let incoming = self.incoming.read().unwrap();
        let edges = self.edges.read().unwrap();

        incoming
            .get(concept)
            .map(|sources| {
                sources
                    .iter()
                    .filter_map(|from| {
                        let key = if from.0 < concept.0 {
                            (*from, *concept)
                        } else {
                            (*concept, *from)
                        };
                        edges.get(&key).cloned()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all edges for a concept (both directions)
    pub fn all_edges_for(&self, concept: &ConceptId) -> Vec<AlexandriaEdge> {
        let mut result = self.edges_from(concept);
        result.extend(self.edges_to(concept));
        result
    }

    /// Edge count
    pub fn edge_count(&self) -> usize {
        let edges = self.edges.read().unwrap();
        edges.len()
    }

    // ========== Usage Tracking ==========

    /// Record a query (creates UserPath edges)
    pub fn record_query(&self, concept_text: &str) {
        let id = self.ensure_concept(concept_text);

        // Access the concept
        {
            let mut concepts = self.concepts.write().unwrap();
            if let Some(concept) = concepts.get_mut(&id) {
                concept.access();
            }
        }

        // Add to current session and get previous query
        let (last, session_snapshot) = {
            let mut session = self.current_session.write().unwrap();
            let last = session.last().cloned();
            session.push(id);
            let snapshot = session.clone();
            (last, snapshot)
        }; // Write lock released here

        // Create UserPath edge to previous query
        if let Some(prev) = last {
            if prev != id {
                self.add_edge(prev, id, EdgeKind::UserPath);
            }
        }

        // Create SessionCorrelation edges to earlier queries
        if session_snapshot.len() > 2 {
            // Find one earlier concept to correlate with
            for i in 0..session_snapshot.len().saturating_sub(2) {
                let earlier = session_snapshot[i];
                if earlier != id {
                    let weight = 1.0 / (session_snapshot.len() - i) as f32;
                    let mut edges = self.edges.write().unwrap();
                    let key = if earlier.0 < id.0 {
                        (earlier, id)
                    } else {
                        (id, earlier)
                    };
                    edges.entry(key).and_modify(|e| {
                        e.weight += weight * 0.1;
                    });
                    break; // Only update once per query
                }
            }
        }
    }

    /// Start a new session (clears session tracking)
    pub fn new_session(&self) {
        let mut session = self.current_session.write().unwrap();
        session.clear();
    }

    /// Get current session
    pub fn current_session(&self) -> Vec<ConceptId> {
        let session = self.current_session.read().unwrap();
        session.clone()
    }

    // ========== Decay ==========

    /// Apply natural decay to all edges
    pub fn apply_decay(&self) {
        let mut edges = self.edges.write().unwrap();

        for edge in edges.values_mut() {
            edge.apply_decay(self.config.decay_half_life_days, self.config.dormant_threshold);
        }
    }

    /// Prune dormant edges (optional - keeps them by default for archaeology)
    pub fn prune_dormant(&self) -> usize {
        let mut edges = self.edges.write().unwrap();
        let before = edges.len();
        edges.retain(|_, e| !e.dormant);
        before - edges.len()
    }

    // ========== Path Finding ==========

    /// BFS to find all concepts reachable within N hops
    pub fn reachable(&self, start: &ConceptId, max_hops: usize) -> HashMap<ConceptId, usize> {
        let mut visited: HashMap<ConceptId, usize> = HashMap::new();
        let mut queue: VecDeque<(ConceptId, usize)> = VecDeque::new();

        queue.push_back((*start, 0));
        visited.insert(*start, 0);

        let outgoing = self.outgoing.read().unwrap();

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }

            if let Some(neighbors) = outgoing.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains_key(neighbor) {
                        visited.insert(*neighbor, depth + 1);
                        queue.push_back((*neighbor, depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// Find shortest path between two concepts
    pub fn find_path(&self, from: &ConceptId, to: &ConceptId) -> Option<Vec<ConceptId>> {
        if from == to {
            return Some(vec![*from]);
        }

        let mut visited: HashSet<ConceptId> = HashSet::new();
        let mut queue: VecDeque<ConceptId> = VecDeque::new();
        let mut parent: HashMap<ConceptId, ConceptId> = HashMap::new();

        queue.push_back(*from);
        visited.insert(*from);

        let outgoing = self.outgoing.read().unwrap();

        while let Some(current) = queue.pop_front() {
            if &current == to {
                // Reconstruct path
                let mut path = vec![current];
                let mut curr = current;
                while let Some(&p) = parent.get(&curr) {
                    path.push(p);
                    curr = p;
                }
                path.reverse();
                return Some(path);
            }

            if let Some(neighbors) = outgoing.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(*neighbor);
                        parent.insert(*neighbor, current);
                        queue.push_back(*neighbor);
                    }
                }
            }
        }

        None
    }

    // ========== Sync ==========

    /// Merge a delta from another node
    pub fn merge_delta(&self, delta: GraphDelta) {
        for update in delta.edge_updates {
            match update {
                EdgeUpdate::New(edge) => {
                    let key = edge.key();
                    let mut edges = self.edges.write().unwrap();

                    edges
                        .entry(key)
                        .and_modify(|existing| {
                            // Merge: combine weights, sources
                            existing.weight += edge.weight * 0.5;
                            for source in &edge.source_nodes {
                                if !existing.source_nodes.contains(source) {
                                    existing.source_nodes.push(*source);
                                }
                            }
                            existing.use_count += edge.use_count;
                            if edge.last_used > existing.last_used {
                                existing.last_used = edge.last_used;
                            }
                        })
                        .or_insert(edge);
                }

                EdgeUpdate::WeightIncrement {
                    from,
                    to,
                    delta: delta_weight,
                    source_node,
                } => {
                    let key = if from.0 < to.0 { (from, to) } else { (to, from) };
                    let mut edges = self.edges.write().unwrap();

                    if let Some(edge) = edges.get_mut(&key) {
                        edge.weight += delta_weight * 0.5;
                        edge.use_count += 1;
                        edge.last_used = delta.timestamp;
                        if !edge.source_nodes.contains(&source_node) {
                            edge.source_nodes.push(source_node);
                        }
                    }
                }

                EdgeUpdate::UsageRefresh { from, to, timestamp } => {
                    let key = if from.0 < to.0 { (from, to) } else { (to, from) };
                    let mut edges = self.edges.write().unwrap();

                    if let Some(edge) = edges.get_mut(&key) {
                        if timestamp > edge.last_used {
                            edge.last_used = timestamp;
                        }
                    }
                }

                EdgeUpdate::MarkDormant { from, to } => {
                    let key = if from.0 < to.0 { (from, to) } else { (to, from) };
                    let mut edges = self.edges.write().unwrap();

                    if let Some(edge) = edges.get_mut(&key) {
                        edge.dormant = true;
                    }
                }
            }
        }
    }

    /// Get pending updates and clear them
    pub fn take_pending_updates(&self) -> Vec<EdgeUpdate> {
        let mut pending = self.pending_updates.write().unwrap();
        std::mem::take(&mut *pending)
    }

    /// Create a delta from pending updates
    pub fn create_delta(&self) -> GraphDelta {
        let updates = self.take_pending_updates();
        let mut seq = self.sequence.write().unwrap();
        *seq += 1;

        GraphDelta {
            from_node: self.local_node,
            timestamp: chrono::Utc::now().timestamp(),
            sequence: *seq,
            new_concepts: Vec::new(), // TODO: track new concepts
            edge_updates: updates,
            wormhole_updates: Vec::new(),
        }
    }

    // ========== Export/Import ==========

    /// Export graph to bytes
    pub fn export(&self) -> Vec<u8> {
        let concepts = self.concepts.read().unwrap();
        let edges = self.edges.read().unwrap();

        let export = GraphExport {
            concepts: concepts.values().cloned().collect(),
            edges: edges.values().cloned().collect(),
            exported_at: chrono::Utc::now().timestamp(),
            from_node: self.local_node,
        };

        serde_json::to_vec(&export).unwrap_or_default()
    }

    /// Import graph from bytes
    pub fn import(&self, data: &[u8]) -> Result<()> {
        let export: GraphExport =
            serde_json::from_slice(data).map_err(|e| Error::SerializationError(e.to_string()))?;

        let mut concepts = self.concepts.write().unwrap();
        let mut edges = self.edges.write().unwrap();
        let mut outgoing = self.outgoing.write().unwrap();
        let mut incoming = self.incoming.write().unwrap();

        for concept in export.concepts {
            concepts.insert(concept.id, concept);
        }

        for edge in export.edges {
            let key = edge.key();
            outgoing.entry(edge.from).or_default().insert(edge.to);
            incoming.entry(edge.to).or_default().insert(edge.from);
            edges.insert(key, edge);
        }

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> GraphStats {
        let concepts = self.concepts.read().unwrap();
        let edges = self.edges.read().unwrap();

        let active_edges = edges.values().filter(|e| !e.dormant).count();
        let multi_source_edges = edges.values().filter(|e| e.source_nodes.len() > 1).count();

        GraphStats {
            concept_count: concepts.len(),
            edge_count: edges.len(),
            active_edges,
            dormant_edges: edges.len() - active_edges,
            multi_source_edges,
        }
    }

    // ========== Persistence ==========

    /// Get default persistence path (~/.gently/alexandria/graph.json)
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gently")
            .join("alexandria")
            .join("graph.json")
    }

    /// Save graph to file
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::IoError(format!("Failed to create directory: {}", e)))?;
        }

        let data = self.export();
        std::fs::write(path, &data)
            .map_err(|e| Error::IoError(format!("Failed to write graph: {}", e)))?;

        tracing::info!(
            "Saved Alexandria graph to {}: {} concepts, {} edges",
            path.display(),
            self.concept_count(),
            self.edge_count()
        );

        Ok(())
    }

    /// Save to default path
    pub fn save_default(&self) -> Result<()> {
        self.save(&Self::default_path())
    }

    /// Load graph from file
    pub fn load(path: &Path, local_node: NodeFingerprint, config: AlexandriaConfig) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| Error::IoError(format!("Failed to read graph: {}", e)))?;

        let graph = Self::new(local_node, config);
        graph.import(&data)?;

        tracing::info!(
            "Loaded Alexandria graph from {}: {} concepts, {} edges",
            path.display(),
            graph.concept_count(),
            graph.edge_count()
        );

        Ok(graph)
    }

    /// Load from default path
    pub fn load_default(local_node: NodeFingerprint, config: AlexandriaConfig) -> Result<Self> {
        Self::load(&Self::default_path(), local_node, config)
    }

    /// Load from file or create new if not exists
    pub fn load_or_create(
        path: &Path,
        local_node: NodeFingerprint,
        config: AlexandriaConfig,
    ) -> Self {
        match Self::load(path, local_node, config.clone()) {
            Ok(graph) => graph,
            Err(e) => {
                tracing::info!("Creating new Alexandria graph ({})", e);
                Self::new(local_node, config)
            }
        }
    }

    /// Load from default path or create new
    pub fn load_or_create_default(local_node: NodeFingerprint, config: AlexandriaConfig) -> Self {
        Self::load_or_create(&Self::default_path(), local_node, config)
    }

    /// Check if a saved graph exists at the path
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Check if a saved graph exists at default path
    pub fn exists_default() -> bool {
        Self::exists(&Self::default_path())
    }
}

#[derive(Serialize, Deserialize)]
struct GraphExport {
    concepts: Vec<Concept>,
    edges: Vec<AlexandriaEdge>,
    exported_at: i64,
    from_node: NodeFingerprint,
}

/// Graph statistics
#[derive(Debug, Clone)]
pub struct GraphStats {
    pub concept_count: usize,
    pub edge_count: usize,
    pub active_edges: usize,
    pub dormant_edges: usize,
    pub multi_source_edges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> NodeFingerprint {
        NodeFingerprint::from_hardware("test", 4, 16, "test123")
    }

    #[test]
    fn test_graph_creation() {
        let graph = AlexandriaGraph::with_defaults(test_node());
        assert_eq!(graph.concept_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_ensure_concept() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        let id1 = graph.ensure_concept("encryption");
        let id2 = graph.ensure_concept("encryption");
        let id3 = graph.ensure_concept("Encryption");

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(graph.concept_count(), 1);
    }

    #[test]
    fn test_add_edge() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        let a = graph.ensure_concept("encryption");
        let b = graph.ensure_concept("security");

        graph.add_edge(a, b, EdgeKind::UserPath);

        assert_eq!(graph.edge_count(), 1);
        assert!(graph.get_edge(&a, &b).is_some());
    }

    #[test]
    fn test_record_query() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        graph.record_query("encryption");
        graph.record_query("security");
        graph.record_query("firewall");

        // Should have 3 concepts
        assert_eq!(graph.concept_count(), 3);

        // Should have 2 UserPath edges (encryption->security, security->firewall)
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn test_path_finding() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        let a = graph.ensure_concept("a");
        let b = graph.ensure_concept("b");
        let c = graph.ensure_concept("c");

        graph.add_edge(a, b, EdgeKind::RelatedTo);
        graph.add_edge(b, c, EdgeKind::RelatedTo);

        let path = graph.find_path(&a, &c);
        assert!(path.is_some());
        assert_eq!(path.unwrap().len(), 3);
    }

    #[test]
    fn test_reachable() {
        let graph = AlexandriaGraph::with_defaults(test_node());

        let a = graph.ensure_concept("a");
        let b = graph.ensure_concept("b");
        let c = graph.ensure_concept("c");
        let d = graph.ensure_concept("d");

        graph.add_edge(a, b, EdgeKind::RelatedTo);
        graph.add_edge(b, c, EdgeKind::RelatedTo);
        graph.add_edge(c, d, EdgeKind::RelatedTo);

        let reachable = graph.reachable(&a, 2);
        assert!(reachable.contains_key(&a));
        assert!(reachable.contains_key(&b));
        assert!(reachable.contains_key(&c));
        assert!(!reachable.contains_key(&d)); // 3 hops, beyond limit
    }

    #[test]
    fn test_persistence_save_load() {
        use std::fs;

        let test_path = PathBuf::from("/tmp/alexandria_test_graph.json");

        // Create and populate a graph
        let graph1 = AlexandriaGraph::with_defaults(test_node());
        graph1.ensure_concept("rust");
        graph1.ensure_concept("programming");
        graph1.ensure_concept("safety");

        let a = graph1.ensure_concept("rust");
        let b = graph1.ensure_concept("programming");
        graph1.add_edge(a, b, EdgeKind::RelatedTo);

        // Save to file
        graph1.save(&test_path).expect("Failed to save graph");

        // Load into new graph
        let graph2 = AlexandriaGraph::load(
            &test_path,
            test_node(),
            AlexandriaConfig::default(),
        ).expect("Failed to load graph");

        // Verify data matches
        assert_eq!(graph2.concept_count(), graph1.concept_count());
        assert_eq!(graph2.edge_count(), graph1.edge_count());
        assert!(graph2.get_edge(&a, &b).is_some());

        // Cleanup
        let _ = fs::remove_file(&test_path);
    }

    #[test]
    fn test_load_or_create() {
        let test_path = PathBuf::from("/tmp/alexandria_nonexistent.json");

        // Should create new graph when file doesn't exist
        let graph = AlexandriaGraph::load_or_create(
            &test_path,
            test_node(),
            AlexandriaConfig::default(),
        );

        assert_eq!(graph.concept_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }
}
