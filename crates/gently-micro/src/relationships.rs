//! # Relationships - Weighted Entity Graph
//!
//! Everything is connected:
//! - Chats relate to files
//! - Files relate to other files
//! - Ideas relate to chats
//! - Everything has weighted edges
//!
//! Weights are determined by:
//! - Content similarity (cosine)
//! - Temporal proximity
//! - Explicit links
//! - Usage patterns

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::idea_extract::Idea;
use crate::Result;

/// Unique identifier for an entity
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityId(String);

impl EntityId {
    /// Create from UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid.to_string())
    }

    /// Create from content (hash-based)
    pub fn from_content(content: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Self(format!("content:{}", hex::encode(&hasher.finalize()[..8])))
    }

    /// Create from path
    pub fn from_path(path: &Path) -> Self {
        Self(format!("path:{}", path.display()))
    }

    /// Create from chat ID
    pub fn from_chat(chat_id: &str) -> Self {
        Self(format!("chat:{}", chat_id))
    }

    /// Create from idea
    pub fn from_idea(idea: &Idea) -> Self {
        Self(format!("idea:{}", idea.id))
    }

    /// Get the raw ID string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get entity type prefix
    pub fn entity_type(&self) -> &str {
        self.0.split(':').next().unwrap_or("unknown")
    }
}

/// An entity in the relationship graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Entity {
    /// A file
    File {
        path: PathBuf,
        domain: Option<String>,
        language: Option<String>,
    },
    /// A chat conversation
    Chat {
        id: String,
        summary: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// An extracted idea
    Idea(Idea),
    /// A content block (arbitrary)
    Content {
        hash: String,
        excerpt: String,
    },
    /// A model in the library
    Model {
        name: String,
        purpose: String,
    },
}

impl Entity {
    /// Get the entity ID
    pub fn id(&self) -> EntityId {
        match self {
            Entity::File { path, .. } => EntityId::from_path(path),
            Entity::Chat { id, .. } => EntityId::from_chat(id),
            Entity::Idea(idea) => EntityId::from_idea(idea),
            Entity::Content { hash, .. } => EntityId(format!("content:{}", hash)),
            Entity::Model { name, .. } => EntityId(format!("model:{}", name)),
        }
    }

    /// Get entity type name
    pub fn type_name(&self) -> &'static str {
        match self {
            Entity::File { .. } => "file",
            Entity::Chat { .. } => "chat",
            Entity::Idea(_) => "idea",
            Entity::Content { .. } => "content",
            Entity::Model { .. } => "model",
        }
    }

    /// Get a text representation for similarity matching
    pub fn to_text(&self) -> String {
        match self {
            Entity::File { path, domain, language } => {
                format!(
                    "{} {} {}",
                    path.display(),
                    domain.as_deref().unwrap_or(""),
                    language.as_deref().unwrap_or("")
                )
            }
            Entity::Chat { summary, .. } => summary.clone(),
            Entity::Idea(idea) => idea.content.clone(),
            Entity::Content { excerpt, .. } => excerpt.clone(),
            Entity::Model { name, purpose } => format!("{} {}", name, purpose),
        }
    }
}

/// A relationship between two entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    /// Source entity
    pub from: EntityId,
    /// Target entity
    pub to: EntityId,
    /// Weight (0.0 - 1.0)
    pub weight: f32,
    /// Type of relationship
    pub relation_type: String,
    /// When created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Times accessed (for boosting)
    pub access_count: u32,
}

impl Relationship {
    /// Create a new relationship
    pub fn new(from: EntityId, to: EntityId, weight: f32, relation_type: &str) -> Self {
        Self {
            from,
            to,
            weight: weight.clamp(0.0, 1.0),
            relation_type: relation_type.to_string(),
            created_at: chrono::Utc::now(),
            access_count: 0,
        }
    }

    /// Record an access (boosts relationship)
    pub fn access(&mut self) {
        self.access_count += 1;
    }

    /// Effective weight (base + usage boost)
    pub fn effective_weight(&self) -> f32 {
        let usage_boost = (self.access_count as f32).ln_1p() * 0.1;
        (self.weight + usage_boost).min(1.0)
    }
}

/// The relationship graph
pub struct RelationshipGraph {
    /// All entities
    entities: HashMap<EntityId, Entity>,
    /// Adjacency list: from -> [(to, relationship)]
    edges: HashMap<EntityId, Vec<Relationship>>,
    /// Reverse index: to -> [from]
    reverse: HashMap<EntityId, Vec<EntityId>>,
    /// Storage directory
    storage_dir: PathBuf,
}

impl RelationshipGraph {
    /// Create a new graph
    pub fn new(storage_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(storage_dir)?;

        let mut graph = Self {
            entities: HashMap::new(),
            edges: HashMap::new(),
            reverse: HashMap::new(),
            storage_dir: storage_dir.to_path_buf(),
        };
        graph.load()?;
        Ok(graph)
    }

    /// Add an entity to the graph
    pub fn add_entity(&mut self, entity: Entity) -> Result<EntityId> {
        let id = entity.id();
        self.entities.insert(id.clone(), entity);
        self.save()?;
        Ok(id)
    }

    /// Get an entity by ID
    pub fn get_entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.get(id)
    }

    /// Add a relationship between entities
    pub fn add_relationship(
        &mut self,
        from: EntityId,
        to: EntityId,
        weight: f32,
        relation_type: &str,
    ) -> Result<()> {
        let rel = Relationship::new(from.clone(), to.clone(), weight, relation_type);

        self.edges.entry(from.clone()).or_default().push(rel);
        self.reverse.entry(to).or_default().push(from);

        self.save()?;
        Ok(())
    }

    /// Get relationships from an entity
    pub fn get_relationships(&self, from: &EntityId) -> &[Relationship] {
        self.edges.get(from).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get entities that relate to this one
    pub fn get_incoming(&self, to: &EntityId) -> Vec<&Relationship> {
        let froms = self.reverse.get(to).cloned().unwrap_or_default();
        let mut rels = Vec::new();
        for from in froms {
            if let Some(edges) = self.edges.get(&from) {
                for rel in edges {
                    if &rel.to == to {
                        rels.push(rel);
                    }
                }
            }
        }
        rels
    }

    /// Find related entities (sorted by weight)
    pub fn find_related(&self, content: &str, limit: usize) -> Result<Vec<(EntityId, f32)>> {
        let content_id = EntityId::from_content(content);
        let content_lower = content.to_lowercase();
        let content_words: std::collections::HashSet<String> =
            content_lower.split_whitespace().map(|s| s.to_string()).collect();

        let mut scores: Vec<(EntityId, f32)> = Vec::new();

        // Score each entity by word overlap
        for (id, entity) in &self.entities {
            if id == &content_id {
                continue;
            }

            let entity_text = entity.to_text().to_lowercase();
            let entity_words: std::collections::HashSet<String> =
                entity_text.split_whitespace().map(|s| s.to_string()).collect();

            // Jaccard similarity
            let intersection = content_words.intersection(&entity_words).count();
            let union = content_words.union(&entity_words).count();

            if union > 0 {
                let similarity = intersection as f32 / union as f32;
                if similarity > 0.1 {
                    scores.push((id.clone(), similarity));
                }
            }
        }

        // Boost scores for entities with explicit relationships
        for (id, score) in &mut scores {
            if let Some(edges) = self.edges.get(id) {
                let avg_weight: f32 = if edges.is_empty() {
                    0.0
                } else {
                    edges.iter().map(|r| r.effective_weight()).sum::<f32>() / edges.len() as f32
                };
                *score = (*score + avg_weight) / 2.0;
            }
        }

        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(limit);

        Ok(scores)
    }

    /// Find path between two entities (BFS)
    pub fn find_path(&self, from: &EntityId, to: &EntityId, max_depth: usize) -> Option<Vec<EntityId>> {
        if from == to {
            return Some(vec![from.clone()]);
        }

        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut parent: HashMap<EntityId, EntityId> = HashMap::new();

        queue.push_back((from.clone(), 0));
        visited.insert(from.clone());

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            if let Some(edges) = self.edges.get(&current) {
                for rel in edges {
                    if visited.contains(&rel.to) {
                        continue;
                    }

                    parent.insert(rel.to.clone(), current.clone());
                    if &rel.to == to {
                        // Reconstruct path
                        let mut path = vec![to.clone()];
                        let mut node = to.clone();
                        while let Some(p) = parent.get(&node) {
                            path.push(p.clone());
                            node = p.clone();
                        }
                        path.reverse();
                        return Some(path);
                    }

                    visited.insert(rel.to.clone());
                    queue.push_back((rel.to.clone(), depth + 1));
                }
            }
        }

        None
    }

    /// Get entities by type
    pub fn get_by_type(&self, type_name: &str) -> Vec<(&EntityId, &Entity)> {
        self.entities
            .iter()
            .filter(|(_, e)| e.type_name() == type_name)
            .collect()
    }

    /// Get graph statistics
    pub fn stats(&self) -> GraphStats {
        let mut entity_types: HashMap<String, usize> = HashMap::new();
        for entity in self.entities.values() {
            *entity_types.entry(entity.type_name().to_string()).or_insert(0) += 1;
        }

        let total_edges: usize = self.edges.values().map(|v| v.len()).sum();
        let avg_weight = if total_edges > 0 {
            self.edges
                .values()
                .flat_map(|v| v.iter().map(|r| r.weight))
                .sum::<f32>()
                / total_edges as f32
        } else {
            0.0
        };

        GraphStats {
            total_entities: self.entities.len(),
            total_edges,
            entity_types,
            avg_weight,
        }
    }

    /// Remove entity and all its relationships
    pub fn remove_entity(&mut self, id: &EntityId) -> Result<()> {
        self.entities.remove(id);
        self.edges.remove(id);
        self.reverse.remove(id);

        // Remove from other adjacency lists
        for edges in self.edges.values_mut() {
            edges.retain(|r| &r.to != id);
        }
        for froms in self.reverse.values_mut() {
            froms.retain(|f| f != id);
        }

        self.save()
    }

    /// Decay old relationships (reduce weight over time)
    pub fn decay(&mut self, factor: f32) -> Result<()> {
        for edges in self.edges.values_mut() {
            for rel in edges.iter_mut() {
                rel.weight *= factor;
            }
            // Remove very weak relationships
            edges.retain(|r| r.weight > 0.01);
        }
        self.save()
    }

    /// Save to disk (atomic: write temp file then rename)
    fn save(&self) -> Result<()> {
        let entities_path = self.storage_dir.join("entities.json");
        let edges_path = self.storage_dir.join("edges.json");
        let entities_tmp = self.storage_dir.join("entities.json.tmp");
        let edges_tmp = self.storage_dir.join("edges.json.tmp");

        // Write to temp files first
        std::fs::write(&entities_tmp, serde_json::to_string_pretty(&self.entities)?)?;
        std::fs::write(&edges_tmp, serde_json::to_string_pretty(&self.edges)?)?;

        // Atomic rename (on most filesystems)
        std::fs::rename(&entities_tmp, &entities_path)?;
        std::fs::rename(&edges_tmp, &edges_path)?;

        Ok(())
    }

    /// Load from disk
    fn load(&mut self) -> Result<()> {
        let entities_path = self.storage_dir.join("entities.json");
        let edges_path = self.storage_dir.join("edges.json");

        if entities_path.exists() {
            let data = std::fs::read_to_string(&entities_path)?;
            self.entities = serde_json::from_str(&data)?;
        }

        if edges_path.exists() {
            let data = std::fs::read_to_string(&edges_path)?;
            self.edges = serde_json::from_str(&data)?;

            // Rebuild reverse index
            for (from, rels) in &self.edges {
                for rel in rels {
                    self.reverse.entry(rel.to.clone()).or_default().push(from.clone());
                }
            }
        }

        Ok(())
    }

    /// Clear all data
    pub fn clear(&mut self) -> Result<()> {
        self.entities.clear();
        self.edges.clear();
        self.reverse.clear();
        self.save()
    }
}

/// Graph statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_entities: usize,
    pub total_edges: usize,
    pub entity_types: HashMap<String, usize>,
    pub avg_weight: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_id() {
        let id1 = EntityId::from_content("test content");
        let id2 = EntityId::from_content("test content");
        assert_eq!(id1, id2);

        let id3 = EntityId::from_content("different content");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_entity_types() {
        let file = Entity::File {
            path: PathBuf::from("/test.rs"),
            domain: Some("test".into()),
            language: Some("rust".into()),
        };
        assert_eq!(file.type_name(), "file");

        let chat = Entity::Chat {
            id: "123".into(),
            summary: "test chat".into(),
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(chat.type_name(), "chat");
    }

    #[test]
    fn test_relationship() {
        let from = EntityId::from_content("a");
        let to = EntityId::from_content("b");
        let mut rel = Relationship::new(from, to, 0.8, "relates_to");

        assert_eq!(rel.weight, 0.8);
        assert_eq!(rel.effective_weight(), 0.8);

        rel.access();
        rel.access();
        assert!(rel.effective_weight() > 0.8);
    }

    #[test]
    fn test_graph() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut graph = RelationshipGraph::new(temp_dir.path()).unwrap();

        // Add entities
        let file = Entity::File {
            path: PathBuf::from("/test.rs"),
            domain: Some("security".into()),
            language: Some("rust".into()),
        };
        let file_id = graph.add_entity(file).unwrap();

        let chat = Entity::Chat {
            id: "123".into(),
            summary: "discussing security implementation".into(),
            timestamp: chrono::Utc::now(),
        };
        let chat_id = graph.add_entity(chat).unwrap();

        // Add relationship
        graph
            .add_relationship(chat_id.clone(), file_id.clone(), 0.9, "references")
            .unwrap();

        // Check relationships
        let rels = graph.get_relationships(&chat_id);
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].to, file_id);
    }

    #[test]
    fn test_find_related() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut graph = RelationshipGraph::new(temp_dir.path()).unwrap();

        // Add some entities
        graph
            .add_entity(Entity::Content {
                hash: "1".into(),
                excerpt: "rust security implementation".into(),
            })
            .unwrap();
        graph
            .add_entity(Entity::Content {
                hash: "2".into(),
                excerpt: "python web framework".into(),
            })
            .unwrap();
        graph
            .add_entity(Entity::Content {
                hash: "3".into(),
                excerpt: "rust crypto library".into(),
            })
            .unwrap();

        // Find related to "rust security"
        let related = graph.find_related("rust security", 10).unwrap();
        assert!(!related.is_empty());
    }

    #[test]
    fn test_find_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut graph = RelationshipGraph::new(temp_dir.path()).unwrap();

        let a = graph
            .add_entity(Entity::Content {
                hash: "a".into(),
                excerpt: "start".into(),
            })
            .unwrap();
        let b = graph
            .add_entity(Entity::Content {
                hash: "b".into(),
                excerpt: "middle".into(),
            })
            .unwrap();
        let c = graph
            .add_entity(Entity::Content {
                hash: "c".into(),
                excerpt: "end".into(),
            })
            .unwrap();

        graph.add_relationship(a.clone(), b.clone(), 0.8, "to").unwrap();
        graph.add_relationship(b.clone(), c.clone(), 0.8, "to").unwrap();

        let path = graph.find_path(&a, &c, 5);
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], a);
        assert_eq!(path[2], c);
    }
}
