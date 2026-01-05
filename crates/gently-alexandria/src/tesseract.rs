//! Tesseract Semantics - Hypercube Navigation for Meaning
//!
//! Traditional vector search looks at the SHADOW of meaning.
//! A 768-dimensional embedding projected to 1D similarity.
//!
//! Tesseract unfolds the hypercube:
//!
//! ```text
//!                    ┌─────────────┐
//!                   ╱│            ╱│
//!                  ╱ │  INNER    ╱ │
//!                 ┌─────────────┐  │
//!                 │  │  CUBE    │  │
//!                 │  │          │  │
//!    ┌────────────│──┼──────────│──┼────────┐
//!   ╱│            │  └──────────│──┘       ╱│
//!  ╱ │    OUTER   │ ╱           │╱        ╱ │
//! ┌──────────────────────────────────────┐  │
//! │  │    CUBE    └─────────────┘        │  │
//! │  │                                   │  │
//! │  │     8 CELLS = 8 CONTEXTS          │  │
//! │  └───────────────────────────────────│──┘
//! │ ╱                                    │ ╱
//! └──────────────────────────────────────┘
//!
//! THE INNER CUBE ROTATES THROUGH THE OUTER
//! THAT'S THE 4TH DIMENSION - TIME/CONTEXT
//! ```
//!
//! ## The 8 Faces (Cells)
//!
//! ```text
//! +1 ACTUAL      What it IS (current meaning)
//! -1 ELIMINATED  What it ISN'T (ruled out meanings)
//!  0 POTENTIAL   What it COULD BE (latent meanings)
//!  ∞ TEMPORAL    WHEN it matters (time-dependent meaning)
//!    OBSERVER    WHO cares (perspective-dependent)
//!    CONTEXT     WHERE it lives (domain-dependent)
//!    METHOD      HOW it works (procedural meaning)
//!    PURPOSE     WHY it exists (teleological meaning)
//! ```
//!
//! ## Example: "Crypto" Through Time
//!
//! ```text
//! "Crypto" in 2015:
//! ├── ACTUAL: cryptography, RSA, AES, security
//! ├── ELIMINATED: currency, investment
//! ├── TEMPORAL: pre-Bitcoin-mainstream
//! └── CONTEXT: military, academia, security
//!
//! "Crypto" in 2021:
//! ├── ACTUAL: bitcoin, NFT, wallet, blockchain
//! ├── ELIMINATED: (cryptography now needs qualifier)
//! ├── TEMPORAL: bull market, NFT boom
//! └── CONTEXT: finance, speculation, twitter
//!
//! SAME WORD. DIFFERENT CELL IN THE HYPERCUBE.
//! THE TESSERACT HOLDS BOTH WITHOUT CONTRADICTION.
//! ```

use crate::{ConceptId, AlexandriaEdge, EdgeKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Embedding dimensions per face (384 total / 8 faces = 48 per face)
pub const DIMS_PER_FACE: usize = 48;

/// Total embedding dimensions (BGE-small = 384)
pub const TOTAL_DIMS: usize = 384;

/// Face embeddings - 8 faces with 48 dimensions each
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceEmbeddings {
    /// ACTUAL (+1): What it IS - dims 0-47
    pub actual: Vec<f32>,
    /// ELIMINATED (-1): What it ISN'T - dims 48-95
    pub eliminated: Vec<f32>,
    /// POTENTIAL (0): What it COULD BE - dims 96-143
    pub potential: Vec<f32>,
    /// TEMPORAL (∞): WHEN it matters - dims 144-191
    pub temporal: Vec<f32>,
    /// OBSERVER (WHO): Who cares - dims 192-239
    pub observer: Vec<f32>,
    /// CONTEXT (WHERE): Where it lives - dims 240-287
    pub context: Vec<f32>,
    /// METHOD (HOW): How it works - dims 288-335
    pub method: Vec<f32>,
    /// PURPOSE (WHY): Why it exists - dims 336-383
    pub purpose: Vec<f32>,
}

impl Default for FaceEmbeddings {
    fn default() -> Self {
        Self {
            actual: vec![0.0; DIMS_PER_FACE],
            eliminated: vec![0.0; DIMS_PER_FACE],
            potential: vec![0.0; DIMS_PER_FACE],
            temporal: vec![0.0; DIMS_PER_FACE],
            observer: vec![0.0; DIMS_PER_FACE],
            context: vec![0.0; DIMS_PER_FACE],
            method: vec![0.0; DIMS_PER_FACE],
            purpose: vec![0.0; DIMS_PER_FACE],
        }
    }
}

impl FaceEmbeddings {
    /// Create from a 384-dimensional embedding
    pub fn from_embedding(embedding: &[f32]) -> Self {
        let mut faces = Self::default();

        if embedding.len() >= TOTAL_DIMS {
            faces.actual = embedding[0..48].to_vec();
            faces.eliminated = embedding[48..96].to_vec();
            faces.potential = embedding[96..144].to_vec();
            faces.temporal = embedding[144..192].to_vec();
            faces.observer = embedding[192..240].to_vec();
            faces.context = embedding[240..288].to_vec();
            faces.method = embedding[288..336].to_vec();
            faces.purpose = embedding[336..384].to_vec();
        }

        faces
    }

    /// Convert back to a flat embedding
    pub fn to_embedding(&self) -> Vec<f32> {
        let mut result = Vec::with_capacity(TOTAL_DIMS);
        result.extend_from_slice(&self.actual);
        result.extend_from_slice(&self.eliminated);
        result.extend_from_slice(&self.potential);
        result.extend_from_slice(&self.temporal);
        result.extend_from_slice(&self.observer);
        result.extend_from_slice(&self.context);
        result.extend_from_slice(&self.method);
        result.extend_from_slice(&self.purpose);
        result
    }

    /// Get embedding for a specific face
    pub fn get_face(&self, face: HyperFace) -> &[f32] {
        match face {
            HyperFace::Actual => &self.actual,
            HyperFace::Eliminated => &self.eliminated,
            HyperFace::Potential => &self.potential,
            HyperFace::Temporal => &self.temporal,
            HyperFace::Observer => &self.observer,
            HyperFace::Context => &self.context,
            HyperFace::Method => &self.method,
            HyperFace::Purpose => &self.purpose,
        }
    }

    /// Cosine similarity for a specific face
    pub fn face_similarity(&self, other: &FaceEmbeddings, face: HyperFace) -> f32 {
        let a = self.get_face(face);
        let b = other.get_face(face);
        cosine_similarity(a, b)
    }

    /// Overall similarity across all faces
    pub fn total_similarity(&self, other: &FaceEmbeddings) -> f32 {
        let a = self.to_embedding();
        let b = other.to_embedding();
        cosine_similarity(&a, &b)
    }
}

/// Cosine similarity for arbitrary vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

/// A position in the semantic hypercube
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperPosition {
    /// Concept being positioned
    pub concept: ConceptId,

    /// Position in each of the 8 faces (concept-based)
    pub actual: Vec<ConceptId>,      // +1: What it IS
    pub eliminated: Vec<ConceptId>,  // -1: What it ISN'T
    pub potential: Vec<ConceptId>,   //  0: What it COULD BE
    pub temporal: TemporalPosition,  //  ∞: WHEN context
    pub observer: Vec<String>,       //  WHO cares
    pub context: Vec<String>,        //  WHERE it lives (domains)
    pub method: Vec<ConceptId>,      //  HOW it works
    pub purpose: Vec<ConceptId>,     //  WHY it exists

    /// Full embedding for this position (384 dims)
    pub embedding: Option<Vec<f32>>,

    /// Face embeddings (projected from full embedding)
    pub face_embeddings: Option<FaceEmbeddings>,

    /// When this position was recorded
    pub recorded_at: DateTime<Utc>,
}

impl HyperPosition {
    /// Create a new HyperPosition with an embedding
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.face_embeddings = Some(FaceEmbeddings::from_embedding(&embedding));
        self.embedding = Some(embedding);
        self
    }

    /// Set face embeddings directly
    pub fn with_face_embeddings(mut self, faces: FaceEmbeddings) -> Self {
        self.face_embeddings = Some(faces);
        self
    }

    // === BONEBLOB BIZ Constraint Methods ===

    /// Add an elimination constraint (CIRCLE pass result)
    pub fn add_elimination(&mut self, eliminated_concept: ConceptId) {
        if !self.eliminated.contains(&eliminated_concept) {
            self.eliminated.push(eliminated_concept);
        }
    }

    /// Add multiple eliminations at once
    pub fn add_eliminations(&mut self, concepts: impl IntoIterator<Item = ConceptId>) {
        for c in concepts {
            self.add_elimination(c);
        }
    }

    /// Check if a concept has been eliminated
    pub fn is_eliminated(&self, concept: &ConceptId) -> bool {
        self.eliminated.contains(concept)
    }

    /// Get all eliminations as constraint strings (for BONES preprompt)
    pub fn get_elimination_constraints(&self) -> Vec<String> {
        self.eliminated
            .iter()
            .map(|c| format!("NOT: {:x}", c.0[0] as u32)) // Short form of hash
            .collect()
    }

    /// Calculate remaining search space as ratio (0.0-1.0)
    /// Based on eliminations vs total potential + actual
    pub fn search_space_remaining(&self) -> f32 {
        let total = self.potential.len() + self.actual.len();
        if total == 0 {
            return 1.0; // No known space to eliminate from
        }
        let eliminated = self.eliminated.len();
        1.0 - (eliminated as f32 / (total + eliminated) as f32)
    }

    /// Check if this position has converged (< 1% search space remaining)
    pub fn has_converged(&self) -> bool {
        self.search_space_remaining() < 0.01
    }

    /// Get the elimination face embedding (dims 48-95)
    pub fn elimination_embedding(&self) -> Option<&[f32]> {
        self.face_embeddings.as_ref().map(|f| f.eliminated.as_slice())
    }

    /// Merge eliminations from another position (for accumulation)
    pub fn merge_eliminations(&mut self, other: &HyperPosition) {
        for e in &other.eliminated {
            self.add_elimination(*e);
        }
    }
}

/// Temporal context for a concept
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPosition {
    /// When this meaning was valid from
    pub valid_from: Option<DateTime<Utc>>,

    /// When this meaning was valid until (None = still valid)
    pub valid_until: Option<DateTime<Utc>>,

    /// Era tags (e.g., "pre-internet", "web2", "web3")
    pub era_tags: Vec<String>,

    /// Cultural moment markers
    pub moments: Vec<String>,
}

impl Default for TemporalPosition {
    fn default() -> Self {
        Self {
            valid_from: None,
            valid_until: None,
            era_tags: Vec::new(),
            moments: Vec::new(),
        }
    }
}

/// The semantic tesseract - 8-cell hypercube for navigation
#[derive(Debug, Clone)]
pub struct SemanticTesseract {
    /// All positions indexed by concept
    positions: HashMap<ConceptId, Vec<HyperPosition>>,

    /// Temporal index: era -> concepts active in that era
    temporal_index: HashMap<String, Vec<ConceptId>>,

    /// Observer index: perspective -> concepts
    observer_index: HashMap<String, Vec<ConceptId>>,

    /// Context/domain index
    context_index: HashMap<String, Vec<ConceptId>>,
}

impl SemanticTesseract {
    pub fn new() -> Self {
        Self {
            positions: HashMap::new(),
            temporal_index: HashMap::new(),
            observer_index: HashMap::new(),
            context_index: HashMap::new(),
        }
    }

    /// Record a concept's position in the hypercube
    pub fn record_position(&mut self, position: HyperPosition) {
        let concept = position.concept;

        // Index by temporal era
        for era in &position.temporal.era_tags {
            self.temporal_index
                .entry(era.clone())
                .or_default()
                .push(concept);
        }

        // Index by observer
        for observer in &position.observer {
            self.observer_index
                .entry(observer.clone())
                .or_default()
                .push(concept);
        }

        // Index by context/domain
        for ctx in &position.context {
            self.context_index
                .entry(ctx.clone())
                .or_default()
                .push(concept);
        }

        // Store the position
        self.positions
            .entry(concept)
            .or_default()
            .push(position);
    }

    /// Navigate to a concept and get its full meaning across all faces
    pub fn navigate(&self, concept: &ConceptId) -> Option<FullMeaning> {
        let positions = self.positions.get(concept)?;

        // Get the most recent position
        let current = positions.last()?;

        Some(FullMeaning {
            concept: *concept,
            what_it_is: current.actual.clone(),
            what_it_isnt: current.eliminated.clone(),
            what_it_could_be: current.potential.clone(),
            when_it_matters: current.temporal.clone(),
            who_cares: current.observer.clone(),
            where_it_lives: current.context.clone(),
            how_it_works: current.method.clone(),
            why_it_exists: current.purpose.clone(),
            historical_positions: positions.len(),
        })
    }

    /// Navigate to a concept at a specific time
    pub fn navigate_at(&self, concept: &ConceptId, when: DateTime<Utc>) -> Option<FullMeaning> {
        let positions = self.positions.get(concept)?;

        // Find position valid at that time
        let position = positions.iter().find(|p| {
            let after_start = p.temporal.valid_from
                .map(|t| when >= t)
                .unwrap_or(true);
            let before_end = p.temporal.valid_until
                .map(|t| when <= t)
                .unwrap_or(true);
            after_start && before_end
        })?;

        Some(FullMeaning {
            concept: *concept,
            what_it_is: position.actual.clone(),
            what_it_isnt: position.eliminated.clone(),
            what_it_could_be: position.potential.clone(),
            when_it_matters: position.temporal.clone(),
            who_cares: position.observer.clone(),
            where_it_lives: position.context.clone(),
            how_it_works: position.method.clone(),
            why_it_exists: position.purpose.clone(),
            historical_positions: positions.len(),
        })
    }

    /// Query: "What's NORTH of X in the WHY dimension?"
    /// Returns concepts that X leads to in the PURPOSE face
    pub fn north_in_purpose(&self, concept: &ConceptId) -> Vec<ConceptId> {
        self.positions.get(concept)
            .and_then(|p| p.last())
            .map(|p| p.purpose.clone())
            .unwrap_or_default()
    }

    /// Query: "What's PAST X in the WHEN dimension?"
    /// Returns concepts that X evolved from
    pub fn past_in_temporal(&self, concept: &ConceptId) -> Vec<HyperPosition> {
        self.positions.get(concept)
            .map(|positions| {
                positions.iter()
                    .filter(|p| p.temporal.valid_until.is_some())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Query: "What ELIMINATED X in the -1 face?"
    /// Returns concepts that ruled out X
    pub fn eliminated_by(&self, concept: &ConceptId) -> Vec<ConceptId> {
        // Search all positions where X appears in eliminated
        let mut eliminators = Vec::new();
        for (id, positions) in &self.positions {
            for pos in positions {
                if pos.eliminated.contains(concept) {
                    eliminators.push(*id);
                    break;
                }
            }
        }
        eliminators
    }

    /// Get all concepts in a specific era
    pub fn concepts_in_era(&self, era: &str) -> Vec<ConceptId> {
        self.temporal_index.get(era).cloned().unwrap_or_default()
    }

    /// Get all concepts from a specific observer's perspective
    pub fn concepts_for_observer(&self, observer: &str) -> Vec<ConceptId> {
        self.observer_index.get(observer).cloned().unwrap_or_default()
    }

    /// Get all concepts in a specific domain/context
    pub fn concepts_in_context(&self, context: &str) -> Vec<ConceptId> {
        self.context_index.get(context).cloned().unwrap_or_default()
    }

    // ========== Embedding-Based Navigation ==========

    /// Find similar concepts in a specific face
    pub fn similar_in_face(
        &self,
        embedding: &[f32],
        face: HyperFace,
        top_k: usize,
    ) -> Vec<(ConceptId, f32)> {
        if embedding.len() < TOTAL_DIMS {
            return Vec::new();
        }

        let query_faces = FaceEmbeddings::from_embedding(embedding);
        let mut results: Vec<(ConceptId, f32)> = Vec::new();

        for (concept_id, positions) in &self.positions {
            if let Some(pos) = positions.last() {
                if let Some(ref face_emb) = pos.face_embeddings {
                    let sim = query_faces.face_similarity(face_emb, face);
                    results.push((*concept_id, sim));
                }
            }
        }

        // Sort by similarity descending
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    /// Find similar concepts across all faces (weighted)
    pub fn similar_all_faces(
        &self,
        embedding: &[f32],
        top_k: usize,
    ) -> Vec<(ConceptId, f32)> {
        if embedding.len() < TOTAL_DIMS {
            return Vec::new();
        }

        let query_faces = FaceEmbeddings::from_embedding(embedding);
        let mut results: Vec<(ConceptId, f32)> = Vec::new();

        for (concept_id, positions) in &self.positions {
            if let Some(pos) = positions.last() {
                if let Some(ref face_emb) = pos.face_embeddings {
                    let sim = query_faces.total_similarity(face_emb);
                    results.push((*concept_id, sim));
                }
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    /// Find concepts with strong signal in a specific face
    /// (high magnitude in that face's embedding dimensions)
    pub fn strongest_in_face(&self, face: HyperFace, top_k: usize) -> Vec<(ConceptId, f32)> {
        let mut results: Vec<(ConceptId, f32)> = Vec::new();

        for (concept_id, positions) in &self.positions {
            if let Some(pos) = positions.last() {
                if let Some(ref face_emb) = pos.face_embeddings {
                    let face_vec = face_emb.get_face(face);
                    let magnitude: f32 = face_vec.iter().map(|x| x * x).sum::<f32>().sqrt();
                    results.push((*concept_id, magnitude));
                }
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    /// Multi-face query: find concepts similar in multiple faces at once
    pub fn multi_face_search(
        &self,
        embedding: &[f32],
        faces: &[HyperFace],
        top_k: usize,
    ) -> Vec<(ConceptId, f32)> {
        if embedding.len() < TOTAL_DIMS || faces.is_empty() {
            return Vec::new();
        }

        let query_faces = FaceEmbeddings::from_embedding(embedding);
        let mut results: Vec<(ConceptId, f32)> = Vec::new();

        for (concept_id, positions) in &self.positions {
            if let Some(pos) = positions.last() {
                if let Some(ref face_emb) = pos.face_embeddings {
                    // Average similarity across requested faces
                    let avg_sim: f32 = faces.iter()
                        .map(|&f| query_faces.face_similarity(face_emb, f))
                        .sum::<f32>() / faces.len() as f32;
                    results.push((*concept_id, avg_sim));
                }
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    /// Get the face that most distinguishes a concept (highest magnitude)
    pub fn dominant_face(&self, concept: &ConceptId) -> Option<(HyperFace, f32)> {
        let positions = self.positions.get(concept)?;
        let pos = positions.last()?;
        let face_emb = pos.face_embeddings.as_ref()?;

        let all_faces = [
            HyperFace::Actual,
            HyperFace::Eliminated,
            HyperFace::Potential,
            HyperFace::Temporal,
            HyperFace::Observer,
            HyperFace::Context,
            HyperFace::Method,
            HyperFace::Purpose,
        ];

        let mut best: Option<(HyperFace, f32)> = None;
        for face in all_faces {
            let vec = face_emb.get_face(face);
            let magnitude: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
            match best {
                None => best = Some((face, magnitude)),
                Some((_, best_mag)) if magnitude > best_mag => best = Some((face, magnitude)),
                _ => {}
            }
        }
        best
    }

    /// Semantic drift: how has a concept's position changed over time?
    pub fn drift_analysis(&self, concept: &ConceptId) -> Option<HyperDriftAnalysis> {
        let positions = self.positions.get(concept)?;
        if positions.len() < 2 {
            return None;
        }

        let first = positions.first()?;
        let last = positions.last()?;

        // Calculate drift in each dimension
        let actual_drift = self.set_difference(&first.actual, &last.actual);
        let context_drift = self.string_set_difference(&first.context, &last.context);
        let observer_drift = self.string_set_difference(&first.observer, &last.observer);

        Some(HyperDriftAnalysis {
            concept: *concept,
            positions_recorded: positions.len(),
            first_recorded: first.recorded_at,
            last_recorded: last.recorded_at,
            actual_added: actual_drift.0,
            actual_removed: actual_drift.1,
            contexts_added: context_drift.0,
            contexts_removed: context_drift.1,
            observers_added: observer_drift.0,
            observers_removed: observer_drift.1,
        })
    }

    fn set_difference(&self, old: &[ConceptId], new: &[ConceptId]) -> (Vec<ConceptId>, Vec<ConceptId>) {
        let added: Vec<_> = new.iter().filter(|c| !old.contains(c)).cloned().collect();
        let removed: Vec<_> = old.iter().filter(|c| !new.contains(c)).cloned().collect();
        (added, removed)
    }

    fn string_set_difference(&self, old: &[String], new: &[String]) -> (Vec<String>, Vec<String>) {
        let added: Vec<_> = new.iter().filter(|c| !old.contains(c)).cloned().collect();
        let removed: Vec<_> = old.iter().filter(|c| !new.contains(c)).cloned().collect();
        (added, removed)
    }

    // ========== 5W Dimensional Query Helpers ==========

    /// Map a 5W dimension name to the corresponding HyperFace
    pub fn dimension_to_face(dimension: &str) -> Option<HyperFace> {
        match dimension.to_lowercase().as_str() {
            "who" => Some(HyperFace::Observer),
            "what" => Some(HyperFace::Actual),
            "where" => Some(HyperFace::Context),
            "when" => Some(HyperFace::Temporal),
            "why" => Some(HyperFace::Purpose),
            "how" => Some(HyperFace::Method),
            "is" | "actual" => Some(HyperFace::Actual),
            "isnt" | "isn't" | "eliminated" => Some(HyperFace::Eliminated),
            "potential" | "could" => Some(HyperFace::Potential),
            _ => None,
        }
    }

    /// Map a HyperFace to its 5W dimension name
    pub fn face_to_dimension(face: HyperFace) -> &'static str {
        match face {
            HyperFace::Observer => "who",
            HyperFace::Actual => "what",
            HyperFace::Context => "where",
            HyperFace::Temporal => "when",
            HyperFace::Purpose => "why",
            HyperFace::Method => "how",
            HyperFace::Eliminated => "isnt",
            HyperFace::Potential => "could",
        }
    }

    /// Query concepts matching a 5W dimension value
    /// Example: query_5w("who", "developers") -> all concepts where observer = "developers"
    pub fn query_5w(&self, dimension: &str, value: &str) -> Vec<ConceptId> {
        match Self::dimension_to_face(dimension) {
            Some(HyperFace::Observer) => self.concepts_for_observer(value),
            Some(HyperFace::Context) => self.concepts_in_context(value),
            Some(HyperFace::Temporal) => self.concepts_in_era(value),
            Some(HyperFace::Actual) => self.concepts_with_actual(value),
            Some(HyperFace::Purpose) => self.concepts_with_purpose(value),
            Some(HyperFace::Method) => self.concepts_with_method(value),
            Some(HyperFace::Eliminated) => self.concepts_with_elimination(value),
            Some(HyperFace::Potential) => self.concepts_with_potential(value),
            None => Vec::new(),
        }
    }

    /// Get all concepts that have a specific actual value (by string match)
    fn concepts_with_actual(&self, value: &str) -> Vec<ConceptId> {
        let target = ConceptId::from_concept(value);
        self.positions.iter()
            .filter(|(_, positions)| {
                positions.iter().any(|p| p.actual.contains(&target))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all concepts that have a specific purpose (by string match)
    fn concepts_with_purpose(&self, value: &str) -> Vec<ConceptId> {
        let target = ConceptId::from_concept(value);
        self.positions.iter()
            .filter(|(_, positions)| {
                positions.iter().any(|p| p.purpose.contains(&target))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all concepts that use a specific method
    fn concepts_with_method(&self, value: &str) -> Vec<ConceptId> {
        let target = ConceptId::from_concept(value);
        self.positions.iter()
            .filter(|(_, positions)| {
                positions.iter().any(|p| p.method.contains(&target))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all concepts where something has been eliminated
    fn concepts_with_elimination(&self, value: &str) -> Vec<ConceptId> {
        let target = ConceptId::from_concept(value);
        self.positions.iter()
            .filter(|(_, positions)| {
                positions.iter().any(|p| p.eliminated.contains(&target))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get all concepts with a specific potential
    fn concepts_with_potential(&self, value: &str) -> Vec<ConceptId> {
        let target = ConceptId::from_concept(value);
        self.positions.iter()
            .filter(|(_, positions)| {
                positions.iter().any(|p| p.potential.contains(&target))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Multi-dimensional 5W query - find concepts matching ALL specified dimensions
    /// Example: query_5w_multi(&[("who", "developers"), ("where", "tech")])
    ///          -> concepts where observer=developers AND context=tech
    pub fn query_5w_multi(&self, dimensions: &[(&str, &str)]) -> Vec<ConceptId> {
        if dimensions.is_empty() {
            return Vec::new();
        }

        // Start with first dimension
        let (first_dim, first_val) = dimensions[0];
        let mut results: std::collections::HashSet<ConceptId> =
            self.query_5w(first_dim, first_val).into_iter().collect();

        // Intersect with remaining dimensions
        for (dim, val) in &dimensions[1..] {
            let candidates: std::collections::HashSet<ConceptId> =
                self.query_5w(dim, val).into_iter().collect();
            results = results.intersection(&candidates).copied().collect();
        }

        results.into_iter().collect()
    }

    /// Get all unique values for a 5W dimension
    pub fn dimension_values(&self, dimension: &str) -> Vec<String> {
        match Self::dimension_to_face(dimension) {
            Some(HyperFace::Observer) => {
                self.observer_index.keys().cloned().collect()
            }
            Some(HyperFace::Context) => {
                self.context_index.keys().cloned().collect()
            }
            Some(HyperFace::Temporal) => {
                self.temporal_index.keys().cloned().collect()
            }
            _ => Vec::new(),
        }
    }

    /// Convert an edge to a hypercube navigation
    pub fn edge_to_navigation(&self, edge: &AlexandriaEdge) -> HyperNavigation {
        let face = match &edge.kind {
            EdgeKind::IsA | EdgeKind::DerivedFrom => HyperFace::Actual,
            EdgeKind::Contradicts => HyperFace::Eliminated,
            EdgeKind::RelatedTo | EdgeKind::Enables => HyperFace::Potential,
            EdgeKind::LeadsTo | EdgeKind::Causes => HyperFace::Purpose,
            EdgeKind::Requires | EdgeKind::PartOf => HyperFace::Method,
            EdgeKind::UsedIn => HyperFace::Context,
            EdgeKind::UserPath | EdgeKind::SessionCorrelation => HyperFace::Observer,
            _ => HyperFace::Actual,
        };

        HyperNavigation {
            from: edge.from,
            to: edge.to,
            face,
            weight: edge.weight,
        }
    }
}

/// Full meaning of a concept across all 8 faces
#[derive(Debug, Clone)]
pub struct FullMeaning {
    pub concept: ConceptId,
    pub what_it_is: Vec<ConceptId>,      // ACTUAL
    pub what_it_isnt: Vec<ConceptId>,    // ELIMINATED
    pub what_it_could_be: Vec<ConceptId>, // POTENTIAL
    pub when_it_matters: TemporalPosition, // TEMPORAL
    pub who_cares: Vec<String>,          // OBSERVER
    pub where_it_lives: Vec<String>,     // CONTEXT
    pub how_it_works: Vec<ConceptId>,    // METHOD
    pub why_it_exists: Vec<ConceptId>,   // PURPOSE
    pub historical_positions: usize,
}

/// Analysis of how a concept has drifted through time in the hypercube
#[derive(Debug, Clone)]
pub struct HyperDriftAnalysis {
    pub concept: ConceptId,
    pub positions_recorded: usize,
    pub first_recorded: DateTime<Utc>,
    pub last_recorded: DateTime<Utc>,
    pub actual_added: Vec<ConceptId>,
    pub actual_removed: Vec<ConceptId>,
    pub contexts_added: Vec<String>,
    pub contexts_removed: Vec<String>,
    pub observers_added: Vec<String>,
    pub observers_removed: Vec<String>,
}

/// The 8 faces of the semantic hypercube
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HyperFace {
    Actual,     // +1: What it IS
    Eliminated, // -1: What it ISN'T
    Potential,  //  0: What it COULD BE
    Temporal,   //  ∞: WHEN
    Observer,   //  WHO
    Context,    //  WHERE
    Method,     //  HOW
    Purpose,    //  WHY
}

impl std::fmt::Display for HyperFace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HyperFace::Actual => write!(f, "ACTUAL (+1)"),
            HyperFace::Eliminated => write!(f, "ELIMINATED (-1)"),
            HyperFace::Potential => write!(f, "POTENTIAL (0)"),
            HyperFace::Temporal => write!(f, "TEMPORAL (∞)"),
            HyperFace::Observer => write!(f, "OBSERVER (WHO)"),
            HyperFace::Context => write!(f, "CONTEXT (WHERE)"),
            HyperFace::Method => write!(f, "METHOD (HOW)"),
            HyperFace::Purpose => write!(f, "PURPOSE (WHY)"),
        }
    }
}

/// A navigation step through the hypercube
#[derive(Debug, Clone)]
pub struct HyperNavigation {
    pub from: ConceptId,
    pub to: ConceptId,
    pub face: HyperFace,
    pub weight: f32,
}

/// Query builder for hypercube navigation
pub struct HyperQuery {
    concept: Option<ConceptId>,
    face: Option<HyperFace>,
    era: Option<String>,
    observer: Option<String>,
    context: Option<String>,
    at_time: Option<DateTime<Utc>>,
}

impl HyperQuery {
    pub fn new() -> Self {
        Self {
            concept: None,
            face: None,
            era: None,
            observer: None,
            context: None,
            at_time: None,
        }
    }

    pub fn concept(mut self, id: ConceptId) -> Self {
        self.concept = Some(id);
        self
    }

    pub fn in_face(mut self, face: HyperFace) -> Self {
        self.face = Some(face);
        self
    }

    pub fn in_era(mut self, era: impl Into<String>) -> Self {
        self.era = Some(era.into());
        self
    }

    pub fn from_observer(mut self, observer: impl Into<String>) -> Self {
        self.observer = Some(observer.into());
        self
    }

    pub fn in_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn at_time(mut self, when: DateTime<Utc>) -> Self {
        self.at_time = Some(when);
        self
    }

    /// Execute the query
    pub fn execute(self, tesseract: &SemanticTesseract) -> HyperQueryResult {
        let mut results = Vec::new();

        if let Some(concept) = self.concept {
            // Navigate to specific concept
            let meaning = if let Some(when) = self.at_time {
                tesseract.navigate_at(&concept, when)
            } else {
                tesseract.navigate(&concept)
            };

            if let Some(m) = meaning {
                // Filter by face if specified
                if let Some(face) = self.face {
                    match face {
                        HyperFace::Actual => results.extend(m.what_it_is),
                        HyperFace::Eliminated => results.extend(m.what_it_isnt),
                        HyperFace::Potential => results.extend(m.what_it_could_be),
                        HyperFace::Method => results.extend(m.how_it_works),
                        HyperFace::Purpose => results.extend(m.why_it_exists),
                        _ => results.push(concept),
                    }
                } else {
                    results.push(concept);
                }
            }
        } else if let Some(ref era) = self.era {
            results.extend(tesseract.concepts_in_era(era));
        } else if let Some(observer) = self.observer {
            results.extend(tesseract.concepts_for_observer(&observer));
        } else if let Some(context) = self.context {
            results.extend(tesseract.concepts_in_context(&context));
        }

        HyperQueryResult {
            concepts: results,
            face: self.face,
            temporal_context: self.era,
        }
    }
}

/// Result of a hypercube query
#[derive(Debug, Clone)]
pub struct HyperQueryResult {
    pub concepts: Vec<ConceptId>,
    pub face: Option<HyperFace>,
    pub temporal_context: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_concept(text: &str) -> ConceptId {
        ConceptId::from_concept(text)
    }

    #[test]
    fn test_record_and_navigate() {
        let mut tesseract = SemanticTesseract::new();

        let crypto = make_concept("crypto");
        let bitcoin = make_concept("bitcoin");
        let rsa = make_concept("RSA");
        let nft = make_concept("NFT");

        // Record crypto's position in 2015
        let pos_2015 = HyperPosition {
            concept: crypto,
            actual: vec![rsa, make_concept("cryptography")],
            eliminated: vec![bitcoin],
            potential: vec![],
            temporal: TemporalPosition {
                valid_from: None,
                valid_until: Some(Utc::now()),
                era_tags: vec!["pre-mainstream-crypto".to_string()],
                moments: vec![],
            },
            observer: vec!["security".to_string(), "academia".to_string()],
            context: vec!["military".to_string(), "infosec".to_string()],
            method: vec![],
            purpose: vec![make_concept("protect secrets")],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos_2015);

        // Record crypto's position in 2021
        let pos_2021 = HyperPosition {
            concept: crypto,
            actual: vec![bitcoin, nft, make_concept("wallet")],
            eliminated: vec![rsa], // Now needs "cryptography" qualifier
            potential: vec![make_concept("metaverse")],
            temporal: TemporalPosition {
                valid_from: Some(Utc::now()),
                valid_until: None,
                era_tags: vec!["web3".to_string(), "nft-boom".to_string()],
                moments: vec!["bull market".to_string()],
            },
            observer: vec!["finance".to_string(), "twitter".to_string()],
            context: vec!["speculation".to_string(), "defi".to_string()],
            method: vec![make_concept("blockchain")],
            purpose: vec![make_concept("make money")],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos_2021);

        // Navigate to crypto
        let meaning = tesseract.navigate(&crypto).unwrap();

        // Current meaning (2021) should be bitcoin/nft
        assert!(meaning.what_it_is.contains(&bitcoin));
        assert!(meaning.what_it_is.contains(&nft));

        // RSA should now be in "what it isn't"
        assert!(meaning.what_it_isnt.contains(&rsa));

        // Should have 2 historical positions
        assert_eq!(meaning.historical_positions, 2);
    }

    #[test]
    fn test_era_navigation() {
        let mut tesseract = SemanticTesseract::new();

        let ai = make_concept("AI");

        let pos = HyperPosition {
            concept: ai,
            actual: vec![make_concept("LLM"), make_concept("ChatGPT")],
            eliminated: vec![],
            potential: vec![make_concept("AGI")],
            temporal: TemporalPosition {
                valid_from: Some(Utc::now()),
                valid_until: None,
                era_tags: vec!["post-ChatGPT".to_string()],
                moments: vec!["AI hype 2023".to_string()],
            },
            observer: vec!["developers".to_string()],
            context: vec!["tech".to_string()],
            method: vec![make_concept("transformers")],
            purpose: vec![make_concept("automation")],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos);

        // Query by era
        let concepts = tesseract.concepts_in_era("post-ChatGPT");
        assert!(concepts.contains(&ai));
    }

    #[test]
    fn test_drift_analysis() {
        let mut tesseract = SemanticTesseract::new();

        let web = make_concept("web");

        // Web in 2005
        let pos1 = HyperPosition {
            concept: web,
            actual: vec![make_concept("websites"), make_concept("HTML")],
            eliminated: vec![],
            potential: vec![make_concept("web2.0")],
            temporal: TemporalPosition::default(),
            observer: vec!["developers".to_string()],
            context: vec!["internet".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos1);

        // Web in 2023
        let pos2 = HyperPosition {
            concept: web,
            actual: vec![make_concept("web3"), make_concept("dApps")],
            eliminated: vec![make_concept("static sites")],
            potential: vec![make_concept("spatial web")],
            temporal: TemporalPosition::default(),
            observer: vec!["crypto twitter".to_string()],
            context: vec!["blockchain".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos2);

        // Analyze drift
        let drift = tesseract.drift_analysis(&web).unwrap();
        assert_eq!(drift.positions_recorded, 2);
        assert!(!drift.actual_added.is_empty());
        assert!(!drift.contexts_added.is_empty());
    }

    #[test]
    fn test_hyper_query() {
        let mut tesseract = SemanticTesseract::new();

        let rust = make_concept("rust");
        let safety = make_concept("memory safety");

        let pos = HyperPosition {
            concept: rust,
            actual: vec![make_concept("systems programming")],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition {
                era_tags: vec!["post-2015".to_string()],
                ..Default::default()
            },
            observer: vec!["systems programmers".to_string()],
            context: vec!["low-level".to_string()],
            method: vec![make_concept("borrow checker")],
            purpose: vec![safety],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos);

        // Query: What's in rust's PURPOSE face?
        let result = HyperQuery::new()
            .concept(rust)
            .in_face(HyperFace::Purpose)
            .execute(&tesseract);

        assert!(result.concepts.contains(&safety));
    }

    #[test]
    fn test_face_embeddings() {
        // Create a fake 384-dim embedding
        let embedding: Vec<f32> = (0..384).map(|i| (i as f32 / 384.0) * 2.0 - 1.0).collect();

        let faces = FaceEmbeddings::from_embedding(&embedding);

        // First face should have dims 0-47
        assert!((faces.actual[0] - (-1.0)).abs() < 0.01);
        assert!((faces.actual[47] - ((47.0 / 384.0) * 2.0 - 1.0)).abs() < 0.01);

        // Last face should have dims 336-383
        assert!((faces.purpose[47] - ((383.0 / 384.0) * 2.0 - 1.0)).abs() < 0.01);

        // Roundtrip
        let back = faces.to_embedding();
        assert_eq!(back.len(), 384);
        assert!((back[0] - embedding[0]).abs() < 0.001);
        assert!((back[383] - embedding[383]).abs() < 0.001);
    }

    #[test]
    fn test_face_similarity() {
        let emb1: Vec<f32> = (0..384).map(|i| (i as f32).sin()).collect();
        let emb2: Vec<f32> = (0..384).map(|i| (i as f32).sin()).collect();
        let emb3: Vec<f32> = (0..384).map(|i| (i as f32).cos()).collect();

        let faces1 = FaceEmbeddings::from_embedding(&emb1);
        let faces2 = FaceEmbeddings::from_embedding(&emb2);
        let faces3 = FaceEmbeddings::from_embedding(&emb3);

        // Same embedding should have high similarity
        let sim_same = faces1.face_similarity(&faces2, HyperFace::Actual);
        assert!(sim_same > 0.99);

        // Different embedding should have lower similarity
        let sim_diff = faces1.face_similarity(&faces3, HyperFace::Actual);
        assert!(sim_diff < sim_same);
    }

    #[test]
    fn test_embedding_search() {
        let mut tesseract = SemanticTesseract::new();

        let rust = make_concept("rust");
        let python = make_concept("python");
        let go = make_concept("go");

        // Create embeddings with different patterns
        let rust_emb: Vec<f32> = (0..384).map(|i| (i as f32 * 0.01).sin()).collect();
        let python_emb: Vec<f32> = (0..384).map(|i| (i as f32 * 0.02).sin()).collect();
        let go_emb: Vec<f32> = (0..384).map(|i| (i as f32 * 0.015).sin()).collect();

        let pos_rust = HyperPosition {
            concept: rust,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec![],
            context: vec![],
            method: vec![],
            purpose: vec![],
            embedding: Some(rust_emb.clone()),
            face_embeddings: Some(FaceEmbeddings::from_embedding(&rust_emb)),
            recorded_at: Utc::now(),
        };

        let pos_python = HyperPosition {
            concept: python,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec![],
            context: vec![],
            method: vec![],
            purpose: vec![],
            embedding: Some(python_emb.clone()),
            face_embeddings: Some(FaceEmbeddings::from_embedding(&python_emb)),
            recorded_at: Utc::now(),
        };

        let pos_go = HyperPosition {
            concept: go,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec![],
            context: vec![],
            method: vec![],
            purpose: vec![],
            embedding: Some(go_emb.clone()),
            face_embeddings: Some(FaceEmbeddings::from_embedding(&go_emb)),
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos_rust);
        tesseract.record_position(pos_python);
        tesseract.record_position(pos_go);

        // Search by rust embedding
        let results = tesseract.similar_all_faces(&rust_emb, 3);

        // Should return all 3 concepts
        assert_eq!(results.len(), 3);

        // First result should be rust (exact match)
        assert_eq!(results[0].0, rust);
        assert!(results[0].1 > 0.99);
    }

    #[test]
    fn test_dominant_face() {
        let mut tesseract = SemanticTesseract::new();

        let concept = make_concept("purpose-heavy");

        // Create embedding with high values in PURPOSE face (dims 336-383)
        let mut emb = vec![0.1f32; 384];
        for i in 336..384 {
            emb[i] = 1.0; // High values in PURPOSE face
        }

        let pos = HyperPosition {
            concept,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec![],
            context: vec![],
            method: vec![],
            purpose: vec![],
            embedding: Some(emb.clone()),
            face_embeddings: Some(FaceEmbeddings::from_embedding(&emb)),
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos);

        let (dominant, magnitude) = tesseract.dominant_face(&concept).unwrap();
        assert_eq!(dominant, HyperFace::Purpose);
        assert!(magnitude > 5.0); // sqrt(48 * 1.0^2) ≈ 6.9
    }

    // ========== 5W Dimensional Query Tests ==========

    #[test]
    fn test_dimension_to_face() {
        assert_eq!(SemanticTesseract::dimension_to_face("who"), Some(HyperFace::Observer));
        assert_eq!(SemanticTesseract::dimension_to_face("WHAT"), Some(HyperFace::Actual));
        assert_eq!(SemanticTesseract::dimension_to_face("Where"), Some(HyperFace::Context));
        assert_eq!(SemanticTesseract::dimension_to_face("when"), Some(HyperFace::Temporal));
        assert_eq!(SemanticTesseract::dimension_to_face("why"), Some(HyperFace::Purpose));
        assert_eq!(SemanticTesseract::dimension_to_face("how"), Some(HyperFace::Method));
        assert_eq!(SemanticTesseract::dimension_to_face("unknown"), None);
    }

    #[test]
    fn test_face_to_dimension() {
        assert_eq!(SemanticTesseract::face_to_dimension(HyperFace::Observer), "who");
        assert_eq!(SemanticTesseract::face_to_dimension(HyperFace::Actual), "what");
        assert_eq!(SemanticTesseract::face_to_dimension(HyperFace::Context), "where");
        assert_eq!(SemanticTesseract::face_to_dimension(HyperFace::Temporal), "when");
        assert_eq!(SemanticTesseract::face_to_dimension(HyperFace::Purpose), "why");
    }

    #[test]
    fn test_query_5w() {
        let mut tesseract = SemanticTesseract::new();

        let rust = make_concept("rust");
        let python = make_concept("python");

        let pos_rust = HyperPosition {
            concept: rust,
            actual: vec![make_concept("systems programming")],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition {
                era_tags: vec!["modern".to_string()],
                ..Default::default()
            },
            observer: vec!["developers".to_string(), "systems programmers".to_string()],
            context: vec!["low-level".to_string(), "safety".to_string()],
            method: vec![make_concept("borrow checker")],
            purpose: vec![make_concept("memory safety")],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        let pos_python = HyperPosition {
            concept: python,
            actual: vec![make_concept("scripting")],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition {
                era_tags: vec!["modern".to_string()],
                ..Default::default()
            },
            observer: vec!["developers".to_string(), "data scientists".to_string()],
            context: vec!["high-level".to_string(), "ml".to_string()],
            method: vec![],
            purpose: vec![make_concept("simplicity")],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        };

        tesseract.record_position(pos_rust);
        tesseract.record_position(pos_python);

        // Query WHO = "developers" - should get both
        let devs = tesseract.query_5w("who", "developers");
        assert!(devs.contains(&rust));
        assert!(devs.contains(&python));

        // Query WHO = "systems programmers" - should get only rust
        let sys_devs = tesseract.query_5w("who", "systems programmers");
        assert!(sys_devs.contains(&rust));
        assert!(!sys_devs.contains(&python));

        // Query WHERE = "ml" - should get only python
        let ml = tesseract.query_5w("where", "ml");
        assert!(!ml.contains(&rust));
        assert!(ml.contains(&python));

        // Query WHEN = "modern" - should get both
        let modern = tesseract.query_5w("when", "modern");
        assert!(modern.contains(&rust));
        assert!(modern.contains(&python));
    }

    #[test]
    fn test_query_5w_multi() {
        let mut tesseract = SemanticTesseract::new();

        let rust = make_concept("rust");
        let python = make_concept("python");
        let go = make_concept("go");

        // Setup positions with overlapping dimensions
        tesseract.record_position(HyperPosition {
            concept: rust,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec!["google".to_string(), "systems".to_string()],
            context: vec!["backend".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        });

        tesseract.record_position(HyperPosition {
            concept: python,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec!["google".to_string(), "data".to_string()],
            context: vec!["ml".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        });

        tesseract.record_position(HyperPosition {
            concept: go,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition::default(),
            observer: vec!["google".to_string(), "systems".to_string()],
            context: vec!["backend".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        });

        // Multi-dimensional: WHO=google AND WHERE=backend -> rust, go
        let results = tesseract.query_5w_multi(&[("who", "google"), ("where", "backend")]);
        assert!(results.contains(&rust));
        assert!(results.contains(&go));
        assert!(!results.contains(&python));

        // Multi-dimensional: WHO=google AND WHO=systems -> rust, go
        let results2 = tesseract.query_5w_multi(&[("who", "google"), ("who", "systems")]);
        assert!(results2.contains(&rust));
        assert!(results2.contains(&go));
        assert!(!results2.contains(&python));
    }

    #[test]
    fn test_dimension_values() {
        let mut tesseract = SemanticTesseract::new();

        let rust = make_concept("rust");

        tesseract.record_position(HyperPosition {
            concept: rust,
            actual: vec![],
            eliminated: vec![],
            potential: vec![],
            temporal: TemporalPosition {
                era_tags: vec!["2015+".to_string(), "modern".to_string()],
                ..Default::default()
            },
            observer: vec!["mozilla".to_string(), "aws".to_string()],
            context: vec!["systems".to_string(), "embedded".to_string()],
            method: vec![],
            purpose: vec![],
            embedding: None,
            face_embeddings: None,
            recorded_at: Utc::now(),
        });

        let observers = tesseract.dimension_values("who");
        assert!(observers.contains(&"mozilla".to_string()));
        assert!(observers.contains(&"aws".to_string()));

        let contexts = tesseract.dimension_values("where");
        assert!(contexts.contains(&"systems".to_string()));
        assert!(contexts.contains(&"embedded".to_string()));

        let eras = tesseract.dimension_values("when");
        assert!(eras.contains(&"2015+".to_string()));
        assert!(eras.contains(&"modern".to_string()));
    }
}
