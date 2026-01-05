//! BBBCP Query Language - BONE/BLOB/BIZ/CIRCLE/PIN
//!
//! The Alexandria Protocol's constraint-based search language:
//!
//! ```text
//! ⊙ START query
//! │
//! ├── BONE: Fixed constraints (immutable rules)
//! │   └── From high-quality inference patterns (>= 0.7)
//! │
//! ├── CIRCLE: Eliminations (70% search space reduction)
//! │   └── From Tesseract eliminated face
//! │   └── From low-quality inference steps
//! │
//! ├── BLOB: Search remaining space
//! │   └── Via ContextRouter + Alexandria
//! │
//! ├── PIN: Convergence
//! │   └── argmax(quality) OR aggregate OR sequence
//! │
//! └── BIZ: Chain forward
//!     └── PIN → new BONE for next query
//! │
//! ⊗ STOP
//! ```
//!
//! ## The Math
//!
//! Intelligence = Capability × Constraint / Search Space
//!
//! Each CIRCLE pass eliminates ~70% → After 5 passes: 0.3^5 = 0.24% remaining

use crate::collapse::{CollapseEngine, CollapseResult, CollapsedRow, RowBuilder};
use crate::hyperspace::{Dimension, HyperspaceQuery, HyperspaceQueryBuilder};
use gently_alexandria::ConceptId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// A BONE constraint - immutable rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bone {
    /// Unique identifier
    pub id: Uuid,
    /// Constraint text
    pub text: String,
    /// Source (inference pattern, user-defined, etc.)
    pub source: BoneSource,
    /// Quality score of the pattern that generated this
    pub quality: f32,
    /// When this BONE was created
    pub created_at: DateTime<Utc>,
}

impl Bone {
    /// Create a new BONE from text
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: BoneSource::UserDefined,
            quality: 1.0,
            created_at: Utc::now(),
        }
    }

    /// Create BONE from inference pattern
    pub fn from_inference(text: impl Into<String>, quality: f32) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: BoneSource::Inference,
            quality,
            created_at: Utc::now(),
        }
    }

    /// Create BONE from a PIN result
    pub fn from_pin(text: impl Into<String>, pin_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: BoneSource::PinResult(pin_id),
            quality: 1.0,
            created_at: Utc::now(),
        }
    }

    /// Format as preprompt constraint
    pub fn as_preprompt(&self) -> String {
        format!("[BONE] {}", self.text)
    }
}

/// Source of a BONE constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BoneSource {
    /// User-defined constraint
    UserDefined,
    /// Generated from high-quality inference
    Inference,
    /// Generated from a PIN result
    PinResult(Uuid),
    /// System default
    System,
}

/// A CIRCLE elimination - what to avoid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circle {
    /// Unique identifier
    pub id: Uuid,
    /// What to eliminate
    pub text: String,
    /// Source of the elimination
    pub source: CircleSource,
    /// Confidence in this elimination
    pub confidence: f32,
    /// When this was created
    pub created_at: DateTime<Utc>,
}

impl Circle {
    /// Create a new CIRCLE elimination
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: CircleSource::Manual,
            confidence: 1.0,
            created_at: Utc::now(),
        }
    }

    /// Create from low-quality inference
    pub fn from_inference(text: impl Into<String>, confidence: f32) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: CircleSource::LowQualityInference,
            confidence,
            created_at: Utc::now(),
        }
    }

    /// Create from Tesseract eliminated face
    pub fn from_tesseract(text: impl Into<String>, concept: ConceptId) -> Self {
        Self {
            id: Uuid::new_v4(),
            text: text.into(),
            source: CircleSource::Tesseract(concept),
            confidence: 0.9,
            created_at: Utc::now(),
        }
    }

    /// Format as preprompt constraint
    pub fn as_preprompt(&self) -> String {
        format!("[CIRCLE] AVOID: {}", self.text)
    }
}

/// Source of a CIRCLE elimination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircleSource {
    /// Manual elimination
    Manual,
    /// From low-quality inference
    LowQualityInference,
    /// From Tesseract eliminated face
    Tesseract(ConceptId),
    /// From failed attempt
    FailedAttempt,
}

/// BLOB search space definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobSearch {
    /// Semantic query
    pub query: String,
    /// Domain to search in
    pub domain: Option<String>,
    /// Maximum results
    pub limit: usize,
    /// Minimum quality threshold
    pub quality_threshold: f32,
}

impl BlobSearch {
    /// Create a semantic search
    pub fn semantic(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            domain: None,
            limit: 100,
            quality_threshold: 0.0,
        }
    }

    /// Search in specific domain
    pub fn in_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set result limit
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    /// Set quality threshold
    pub fn quality(mut self, threshold: f32) -> Self {
        self.quality_threshold = threshold;
        self
    }
}

/// PIN convergence strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PinStrategy {
    /// Pick highest quality result
    ArgmaxQuality,
    /// Aggregate all results
    Aggregate,
    /// Return sequence in order
    Sequence,
    /// First N results
    TopN(usize),
    /// Custom scoring function name
    Custom(String),
}

impl Default for PinStrategy {
    fn default() -> Self {
        Self::ArgmaxQuality
    }
}

/// BIZ chain forward configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainForward {
    /// Convert PIN to BONE for next query
    pub to_bone: bool,
    /// Target query to feed into
    pub target_query: Option<String>,
    /// Maximum chain depth
    pub max_depth: usize,
}

impl ChainForward {
    /// Create default chain forward (PIN → BONE)
    pub fn to_bone() -> Self {
        Self {
            to_bone: true,
            target_query: None,
            max_depth: 5,
        }
    }

    /// Chain to a specific query
    pub fn to_query(query: impl Into<String>) -> Self {
        Self {
            to_bone: true,
            target_query: Some(query.into()),
            max_depth: 5,
        }
    }

    /// Set max chain depth
    pub fn depth(mut self, n: usize) -> Self {
        self.max_depth = n;
        self
    }
}

/// A complete BBBCP query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbbcpQuery {
    /// Unique identifier
    pub id: Uuid,
    /// BONE constraints (immutable rules)
    pub bones: Vec<Bone>,
    /// CIRCLE eliminations (what to avoid)
    pub circles: Vec<Circle>,
    /// BLOB search definition
    pub blob: BlobSearch,
    /// PIN convergence strategy
    pub pin: PinStrategy,
    /// BIZ chain forward (optional)
    pub biz: Option<ChainForward>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

impl BbbcpQuery {
    /// Create a new BBBCP query builder
    pub fn builder() -> BbbcpQueryBuilder {
        BbbcpQueryBuilder::new()
    }

    /// Get all BONE constraints as preprompt
    pub fn bones_preprompt(&self) -> String {
        self.bones.iter()
            .map(|b| b.as_preprompt())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get all CIRCLE eliminations as preprompt
    pub fn circles_preprompt(&self) -> String {
        self.circles.iter()
            .map(|c| c.as_preprompt())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get full preprompt
    pub fn full_preprompt(&self) -> String {
        let mut preprompt = String::new();

        if !self.bones.is_empty() {
            preprompt.push_str("## BONES (Immutable Constraints)\n");
            preprompt.push_str(&self.bones_preprompt());
            preprompt.push_str("\n\n");
        }

        if !self.circles.is_empty() {
            preprompt.push_str("## CIRCLE (Eliminate These)\n");
            preprompt.push_str(&self.circles_preprompt());
            preprompt.push_str("\n\n");
        }

        preprompt.push_str(&format!("## Search: {}\n", self.blob.query));

        preprompt
    }
}

/// Builder for BBBCP queries
pub struct BbbcpQueryBuilder {
    bones: Vec<Bone>,
    circles: Vec<Circle>,
    blob: Option<BlobSearch>,
    pin: PinStrategy,
    biz: Option<ChainForward>,
}

impl BbbcpQueryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            bones: Vec::new(),
            circles: Vec::new(),
            blob: None,
            pin: PinStrategy::default(),
            biz: None,
        }
    }

    /// Add a BONE constraint
    pub fn bone(mut self, text: impl Into<String>) -> Self {
        self.bones.push(Bone::new(text));
        self
    }

    /// Add multiple BONEs
    pub fn bones(mut self, texts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for text in texts {
            self.bones.push(Bone::new(text));
        }
        self
    }

    /// Add a CIRCLE elimination
    pub fn circle(mut self, text: impl Into<String>) -> Self {
        self.circles.push(Circle::new(text));
        self
    }

    /// Add multiple CIRCLEs
    pub fn circles(mut self, texts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for text in texts {
            self.circles.push(Circle::new(text));
        }
        self
    }

    /// Set BLOB search
    pub fn blob(mut self, search: BlobSearch) -> Self {
        self.blob = Some(search);
        self
    }

    /// Set PIN strategy
    pub fn pin(mut self, strategy: PinStrategy) -> Self {
        self.pin = strategy;
        self
    }

    /// Set BIZ chain forward
    pub fn biz(mut self, chain: ChainForward) -> Self {
        self.biz = Some(chain);
        self
    }

    /// Build the query
    pub fn build(self) -> BbbcpQuery {
        BbbcpQuery {
            id: Uuid::new_v4(),
            bones: self.bones,
            circles: self.circles,
            blob: self.blob.unwrap_or_else(|| BlobSearch::semantic("")),
            pin: self.pin,
            biz: self.biz,
            created_at: Utc::now(),
        }
    }
}

impl Default for BbbcpQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Output types from BBBCP execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BbbcpOutput {
    /// Single optimized answer
    Answer(OptimizedResponse),
    /// Table from collapse
    Table(CollapseResult),
    /// Conclusion chain
    Chain(ConclusionChain),
}

/// An optimized response from BBBCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedResponse {
    /// Response text
    pub text: String,
    /// Quality score
    pub quality: f32,
    /// Source concepts
    pub sources: Vec<ConceptId>,
    /// Elimination ratio (how much CIRCLE eliminated)
    pub elimination_ratio: f32,
}

/// A chain of conclusions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConclusionChain {
    /// Ordered conclusions
    pub conclusions: Vec<ChainedConclusion>,
    /// Dependencies (index pairs)
    pub dependencies: Vec<(usize, usize)>,
    /// Whether target was reached
    pub target_reached: bool,
}

/// A conclusion in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedConclusion {
    /// Unique identifier
    pub id: Uuid,
    /// Conclusion text
    pub text: String,
    /// Quality score
    pub quality: f32,
    /// Generated BONE (if any)
    pub bone: Option<Bone>,
}

/// Result of executing a BBBCP query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbbcpResult {
    /// Query ID
    pub query_id: Uuid,
    /// Output (answer, table, or chain)
    pub output: BbbcpOutput,
    /// New BONE generated from PIN
    pub new_bone: Option<Bone>,
    /// Execution proof
    pub proof: BbbcpProof,
    /// Elimination ratio (how effective CIRCLE was)
    pub elimination_ratio: f32,
    /// Statistics
    pub stats: BbbcpStats,
}

impl BbbcpResult {
    /// Check if this result can chain forward
    pub fn can_chain(&self) -> bool {
        self.new_bone.is_some()
    }

    /// Get the new BONE for chaining
    pub fn chain_bone(&self) -> Option<&Bone> {
        self.new_bone.as_ref()
    }
}

/// Cryptographic proof of BBBCP execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbbcpProof {
    /// Hash of input query
    pub query_hash: [u8; 32],
    /// Hash of output
    pub output_hash: [u8; 32],
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// BONE count used
    pub bone_count: usize,
    /// CIRCLE count used
    pub circle_count: usize,
}

impl BbbcpProof {
    /// Create proof from query and result
    pub fn new(query: &BbbcpQuery, output: &BbbcpOutput) -> Self {
        let query_hash = Self::hash_query(query);
        let output_hash = Self::hash_output(output);

        Self {
            query_hash,
            output_hash,
            timestamp: Utc::now(),
            bone_count: query.bones.len(),
            circle_count: query.circles.len(),
        }
    }

    fn hash_query(query: &BbbcpQuery) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for bone in &query.bones {
            hasher.update(bone.text.as_bytes());
        }
        for circle in &query.circles {
            hasher.update(circle.text.as_bytes());
        }
        hasher.update(query.blob.query.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn hash_output(output: &BbbcpOutput) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match output {
            BbbcpOutput::Answer(resp) => {
                hasher.update(resp.text.as_bytes());
            }
            BbbcpOutput::Table(result) => {
                hasher.update(format!("{}", result.rows.len()).as_bytes());
            }
            BbbcpOutput::Chain(chain) => {
                for c in &chain.conclusions {
                    hasher.update(c.text.as_bytes());
                }
            }
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Statistics about BBBCP execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BbbcpStats {
    /// Total search space before CIRCLE
    pub initial_space: usize,
    /// Search space after CIRCLE
    pub reduced_space: usize,
    /// Number of BONE constraints applied
    pub bones_applied: usize,
    /// Number of CIRCLE eliminations applied
    pub circles_applied: usize,
    /// Processing time in milliseconds
    pub processing_ms: u64,
    /// Chain depth (if chaining)
    pub chain_depth: usize,
}

impl BbbcpStats {
    /// Calculate elimination ratio
    pub fn elimination_ratio(&self) -> f32 {
        if self.initial_space == 0 {
            0.0
        } else {
            1.0 - (self.reduced_space as f32 / self.initial_space as f32)
        }
    }
}

/// BBBCP execution engine
pub struct BbbcpEngine {
    /// Quality threshold for PIN
    quality_threshold: f32,
    /// Whether to generate BONEs from PINs
    generate_bones: bool,
    /// Maximum chain depth
    max_chain_depth: usize,
}

impl BbbcpEngine {
    /// Create a new BBBCP engine
    pub fn new() -> Self {
        Self {
            quality_threshold: 0.7,
            generate_bones: true,
            max_chain_depth: 5,
        }
    }

    /// Set quality threshold
    pub fn with_quality_threshold(mut self, threshold: f32) -> Self {
        self.quality_threshold = threshold;
        self
    }

    /// Set bone generation
    pub fn with_bone_generation(mut self, generate: bool) -> Self {
        self.generate_bones = generate;
        self
    }

    /// Set max chain depth
    pub fn with_max_chain_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth;
        self
    }

    /// Execute a BBBCP query against data
    pub fn execute(&self, query: &BbbcpQuery, data: &[CollapsedRow]) -> BbbcpResult {
        let start = std::time::Instant::now();
        let initial_space = data.len();

        // Apply CIRCLE eliminations
        let filtered = self.apply_circles(data, &query.circles);
        let reduced_space = filtered.len();

        // Apply PIN strategy
        let (output, new_bone) = self.apply_pin(&query.pin, &filtered, query);

        let elimination_ratio = if initial_space > 0 {
            1.0 - (reduced_space as f32 / initial_space as f32)
        } else {
            0.0
        };

        let stats = BbbcpStats {
            initial_space,
            reduced_space,
            bones_applied: query.bones.len(),
            circles_applied: query.circles.len(),
            processing_ms: start.elapsed().as_millis() as u64,
            chain_depth: 0,
        };

        let proof = BbbcpProof::new(query, &output);

        BbbcpResult {
            query_id: query.id,
            output,
            new_bone,
            proof,
            elimination_ratio,
            stats,
        }
    }

    /// Apply CIRCLE eliminations
    fn apply_circles(&self, data: &[CollapsedRow], circles: &[Circle]) -> Vec<CollapsedRow> {
        if circles.is_empty() {
            return data.to_vec();
        }

        data.iter()
            .filter(|row| {
                // Check if any row value matches a CIRCLE elimination
                !circles.iter().any(|circle| {
                    row.values.values().any(|v| {
                        v.to_lowercase().contains(&circle.text.to_lowercase())
                    })
                })
            })
            .cloned()
            .collect()
    }

    /// Apply PIN strategy and optionally generate BONE
    fn apply_pin(
        &self,
        strategy: &PinStrategy,
        data: &[CollapsedRow],
        query: &BbbcpQuery,
    ) -> (BbbcpOutput, Option<Bone>) {
        if data.is_empty() {
            return (
                BbbcpOutput::Answer(OptimizedResponse {
                    text: "No results found after CIRCLE elimination".to_string(),
                    quality: 0.0,
                    sources: Vec::new(),
                    elimination_ratio: 1.0,
                }),
                None,
            );
        }

        match strategy {
            PinStrategy::ArgmaxQuality => {
                // Find highest quality result
                let best = data.iter()
                    .max_by(|a, b| a.quality_score.partial_cmp(&b.quality_score).unwrap())
                    .unwrap();

                let text = format!(
                    "Best match: {}",
                    best.values.values().next().unwrap_or(&"(empty)".to_string())
                );

                let new_bone = if self.generate_bones && best.quality_score >= self.quality_threshold {
                    Some(Bone::from_inference(
                        format!("ESTABLISHED: {}", text),
                        best.quality_score,
                    ))
                } else {
                    None
                };

                (
                    BbbcpOutput::Answer(OptimizedResponse {
                        text,
                        quality: best.quality_score,
                        sources: best.source_concepts.clone(),
                        elimination_ratio: 0.0, // Calculated later
                    }),
                    new_bone,
                )
            }
            PinStrategy::Aggregate => {
                // Aggregate all results
                let count = data.len();
                let avg_quality = data.iter().map(|r| r.quality_score).sum::<f32>() / count as f32;

                let text = format!("Aggregated {} results, avg quality {:.2}", count, avg_quality);

                let new_bone = if self.generate_bones && avg_quality >= self.quality_threshold {
                    Some(Bone::from_inference(text.clone(), avg_quality))
                } else {
                    None
                };

                (
                    BbbcpOutput::Answer(OptimizedResponse {
                        text,
                        quality: avg_quality,
                        sources: data.iter().flat_map(|r| r.source_concepts.clone()).collect(),
                        elimination_ratio: 0.0,
                    }),
                    new_bone,
                )
            }
            PinStrategy::TopN(n) => {
                // Return top N as table
                let mut sorted: Vec<_> = data.to_vec();
                sorted.sort_by(|a, b| b.quality_score.partial_cmp(&a.quality_score).unwrap());
                sorted.truncate(*n);

                let collapse_engine = CollapseEngine::new().with_bone_generation(false);
                let hyperspace_query = HyperspaceQueryBuilder::new()
                    .enumerate_dim(Dimension::Who)
                    .enumerate_dim(Dimension::What)
                    .enumerate_dim(Dimension::Where)
                    .enumerate_dim(Dimension::When)
                    .enumerate_dim(Dimension::Why)
                    .build();

                let result = collapse_engine.collapse(&hyperspace_query, &sorted);

                let new_bone = if self.generate_bones && !sorted.is_empty() {
                    let avg_quality = sorted.iter().map(|r| r.quality_score).sum::<f32>() / sorted.len() as f32;
                    if avg_quality >= self.quality_threshold {
                        Some(Bone::from_inference(
                            format!("Top {} results with avg quality {:.2}", n, avg_quality),
                            avg_quality,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                };

                (BbbcpOutput::Table(result), new_bone)
            }
            PinStrategy::Sequence => {
                // Return as chain of conclusions
                let conclusions: Vec<ChainedConclusion> = data.iter()
                    .enumerate()
                    .map(|(i, row)| {
                        let text = row.values.values()
                            .map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(" → ");

                        ChainedConclusion {
                            id: Uuid::new_v4(),
                            text,
                            quality: row.quality_score,
                            bone: if row.quality_score >= self.quality_threshold {
                                Some(Bone::from_inference(
                                    format!("Step {}: {}", i + 1, row.values.values().next().unwrap_or(&"".to_string())),
                                    row.quality_score,
                                ))
                            } else {
                                None
                            },
                        }
                    })
                    .collect();

                // Build dependencies (sequential)
                let dependencies: Vec<(usize, usize)> = (0..conclusions.len().saturating_sub(1))
                    .map(|i| (i, i + 1))
                    .collect();

                let chain = ConclusionChain {
                    conclusions,
                    dependencies,
                    target_reached: true,
                };

                (BbbcpOutput::Chain(chain), None)
            }
            PinStrategy::Custom(_name) => {
                // Fallback to argmax for custom strategies
                self.apply_pin(&PinStrategy::ArgmaxQuality, data, query)
            }
        }
    }
}

impl Default for BbbcpEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bone_creation() {
        let bone = Bone::new("Always validate input");
        assert!(bone.text.contains("validate"));
        assert!(matches!(bone.source, BoneSource::UserDefined));

        let inference_bone = Bone::from_inference("Pattern detected", 0.85);
        assert!(matches!(inference_bone.source, BoneSource::Inference));
        assert_eq!(inference_bone.quality, 0.85);
    }

    #[test]
    fn test_circle_creation() {
        let circle = Circle::new("plaintext passwords");
        assert!(circle.text.contains("plaintext"));
        assert!(matches!(circle.source, CircleSource::Manual));

        let inference_circle = Circle::from_inference("bad approach", 0.3);
        assert!(matches!(inference_circle.source, CircleSource::LowQualityInference));
    }

    #[test]
    fn test_bbbcp_query_builder() {
        let query = BbbcpQuery::builder()
            .bone("MUST validate signatures")
            .bone("MUST use HTTPS")
            .circle("plaintext storage")
            .circle("eval() usage")
            .blob(BlobSearch::semantic("JWT authentication").in_domain("security"))
            .pin(PinStrategy::ArgmaxQuality)
            .biz(ChainForward::to_bone())
            .build();

        assert_eq!(query.bones.len(), 2);
        assert_eq!(query.circles.len(), 2);
        assert!(query.biz.is_some());
    }

    #[test]
    fn test_full_preprompt() {
        let query = BbbcpQuery::builder()
            .bone("Rule 1")
            .bone("Rule 2")
            .circle("Avoid 1")
            .blob(BlobSearch::semantic("test query"))
            .build();

        let preprompt = query.full_preprompt();

        assert!(preprompt.contains("BONES"));
        assert!(preprompt.contains("Rule 1"));
        assert!(preprompt.contains("CIRCLE"));
        assert!(preprompt.contains("Avoid 1"));
        assert!(preprompt.contains("Search: test query"));
    }

    #[test]
    fn test_bbbcp_engine_execute() {
        let engine = BbbcpEngine::new();

        let data = vec![
            RowBuilder::new()
                .who("user1")
                .what("jwt-validation")
                .r#where("security")
                .quality(0.9)
                .build(),
            RowBuilder::new()
                .who("user2")
                .what("plaintext-storage")
                .r#where("security")
                .quality(0.4)
                .build(),
            RowBuilder::new()
                .who("user3")
                .what("encryption")
                .r#where("security")
                .quality(0.85)
                .build(),
        ];

        let query = BbbcpQuery::builder()
            .bone("MUST use encryption")
            .circle("plaintext")
            .blob(BlobSearch::semantic("security"))
            .pin(PinStrategy::ArgmaxQuality)
            .build();

        let result = engine.execute(&query, &data);

        // Should have eliminated plaintext row
        assert!(result.elimination_ratio > 0.0);
        assert_eq!(result.stats.circles_applied, 1);
        assert_eq!(result.stats.bones_applied, 1);

        // Should generate new BONE from high-quality result
        assert!(result.new_bone.is_some());
    }

    #[test]
    fn test_bbbcp_top_n() {
        let engine = BbbcpEngine::new();

        let data = vec![
            RowBuilder::new().who("a").quality(0.9).build(),
            RowBuilder::new().who("b").quality(0.8).build(),
            RowBuilder::new().who("c").quality(0.7).build(),
            RowBuilder::new().who("d").quality(0.6).build(),
        ];

        let query = BbbcpQuery::builder()
            .blob(BlobSearch::semantic("test"))
            .pin(PinStrategy::TopN(2))
            .build();

        let result = engine.execute(&query, &data);

        match &result.output {
            BbbcpOutput::Table(collapse) => {
                assert_eq!(collapse.rows.len(), 2);
            }
            _ => panic!("Expected Table output"),
        }
    }

    #[test]
    fn test_bbbcp_sequence() {
        let engine = BbbcpEngine::new();

        let data = vec![
            RowBuilder::new().who("step1").quality(0.9).build(),
            RowBuilder::new().who("step2").quality(0.8).build(),
            RowBuilder::new().who("step3").quality(0.7).build(),
        ];

        let query = BbbcpQuery::builder()
            .blob(BlobSearch::semantic("process"))
            .pin(PinStrategy::Sequence)
            .build();

        let result = engine.execute(&query, &data);

        match &result.output {
            BbbcpOutput::Chain(chain) => {
                assert_eq!(chain.conclusions.len(), 3);
                assert_eq!(chain.dependencies.len(), 2);
                assert!(chain.target_reached);
            }
            _ => panic!("Expected Chain output"),
        }
    }

    #[test]
    fn test_circle_elimination() {
        let engine = BbbcpEngine::new();

        let data = vec![
            RowBuilder::new().what("good-approach").quality(0.9).build(),
            RowBuilder::new().what("bad-approach").quality(0.8).build(),
            RowBuilder::new().what("another-good").quality(0.85).build(),
        ];

        let query = BbbcpQuery::builder()
            .circle("bad")
            .blob(BlobSearch::semantic("test"))
            .pin(PinStrategy::Aggregate)
            .build();

        let result = engine.execute(&query, &data);

        // Should have eliminated 1 out of 3
        assert_eq!(result.stats.initial_space, 3);
        assert_eq!(result.stats.reduced_space, 2);
        assert!((result.elimination_ratio - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_bbbcp_proof() {
        let query = BbbcpQuery::builder()
            .bone("test bone")
            .circle("test circle")
            .blob(BlobSearch::semantic("test"))
            .build();

        let output = BbbcpOutput::Answer(OptimizedResponse {
            text: "test answer".to_string(),
            quality: 0.9,
            sources: vec![],
            elimination_ratio: 0.5,
        });

        let proof = BbbcpProof::new(&query, &output);

        assert_eq!(proof.bone_count, 1);
        assert_eq!(proof.circle_count, 1);
        assert!(proof.query_hash != [0u8; 32]);
        assert!(proof.output_hash != [0u8; 32]);
    }

    #[test]
    fn test_blob_search_builder() {
        let search = BlobSearch::semantic("authentication")
            .in_domain("security")
            .limit(50)
            .quality(0.7);

        assert_eq!(search.query, "authentication");
        assert_eq!(search.domain, Some("security".to_string()));
        assert_eq!(search.limit, 50);
        assert_eq!(search.quality_threshold, 0.7);
    }

    #[test]
    fn test_chain_forward() {
        let chain = ChainForward::to_bone().depth(3);
        assert!(chain.to_bone);
        assert_eq!(chain.max_depth, 3);

        let query_chain = ChainForward::to_query("next-query");
        assert!(query_chain.target_query.is_some());
    }
}
