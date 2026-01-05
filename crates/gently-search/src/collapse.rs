//! Dimensional Collapse - Table Generation from 5W Queries
//!
//! The Alexandria Protocol collapses hyperspace queries into structured tables:
//!
//! ```text
//! 5W Query:
//!   PIN: WHERE = "security"
//!   FILTER: WHEN >= "2025-12-01"
//!   COLLAPSE: [WHERE, WHY]  (remove from output)
//!   ENUMERATE: [WHO, WHAT, WHEN]  (become columns)
//!
//! Result Table:
//! | WHO_anon | WHAT           | WHEN   |
//! |----------|----------------|--------|
//! | user_001 | jwt-validation | Dec 15 |
//! | user_002 | auth-middleware| Dec 22 |
//! ```
//!
//! ## Collapse Operations
//!
//! - **PIN**: Fix a dimension to a specific value (removes from search space)
//! - **FILTER**: Apply conditions (range, contains, etc.)
//! - **COLLAPSE**: Remove dimensions from output (aggregate)
//! - **ENUMERATE**: Expand dimensions into columns

use crate::hyperspace::{Dimension, DimensionFilter, DimensionValue, FilterOp, HyperspaceQuery};
use gently_alexandria::ConceptId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// A single row in a collapsed result table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollapsedRow {
    /// Values for each enumerated dimension
    pub values: HashMap<Dimension, String>,
    /// Source concept IDs that contributed to this row
    pub source_concepts: Vec<ConceptId>,
    /// Quality score (from inference, if available)
    pub quality_score: f32,
    /// When this row was created
    pub created_at: DateTime<Utc>,
}

impl CollapsedRow {
    /// Create a new collapsed row
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            source_concepts: Vec::new(),
            quality_score: 0.0,
            created_at: Utc::now(),
        }
    }

    /// Get value for a dimension
    pub fn get(&self, dim: Dimension) -> Option<&str> {
        self.values.get(&dim).map(|s| s.as_str())
    }

    /// Set value for a dimension
    pub fn set(&mut self, dim: Dimension, value: impl Into<String>) {
        self.values.insert(dim, value.into());
    }

    /// Convert to a vector of values in column order
    pub fn to_row(&self, columns: &[Dimension]) -> Vec<String> {
        columns.iter()
            .map(|d| self.values.get(d).cloned().unwrap_or_default())
            .collect()
    }
}

impl Default for CollapsedRow {
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographic proof of collapse operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollapseProof {
    /// Hash of the query
    pub query_hash: [u8; 32],
    /// Hash of the result
    pub result_hash: [u8; 32],
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Number of source concepts
    pub source_count: usize,
    /// Number of result rows
    pub row_count: usize,
}

impl CollapseProof {
    /// Create a new proof from query and result
    pub fn new(query: &HyperspaceQuery, rows: &[CollapsedRow]) -> Self {
        let query_hash = Self::hash_query(query);
        let result_hash = Self::hash_rows(rows);

        Self {
            query_hash,
            result_hash,
            timestamp: Utc::now(),
            source_count: rows.iter().map(|r| r.source_concepts.len()).sum(),
            row_count: rows.len(),
        }
    }

    fn hash_query(query: &HyperspaceQuery) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Hash pinned dimensions
        for (dim, val) in &query.pin {
            hasher.update(format!("{:?}:{}", dim, val.value).as_bytes());
        }
        // Hash collapsed dimensions
        for dim in &query.collapse {
            hasher.update(format!("collapse:{:?}", dim).as_bytes());
        }
        // Hash enumerated dimensions
        for dim in &query.enumerate {
            hasher.update(format!("enum:{:?}", dim).as_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn hash_rows(rows: &[CollapsedRow]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for row in rows {
            for (dim, val) in &row.values {
                hasher.update(format!("{:?}:{}", dim, val).as_bytes());
            }
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify the proof matches a result
    pub fn verify(&self, rows: &[CollapsedRow]) -> bool {
        let computed = Self::hash_rows(rows);
        self.result_hash == computed
    }
}

/// Result of a collapse operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollapseResult {
    /// Query ID
    pub id: Uuid,
    /// Column headers (enumerated dimensions)
    pub columns: Vec<Dimension>,
    /// Data rows
    pub rows: Vec<CollapsedRow>,
    /// New BONE constraint generated from this PIN (if applicable)
    pub new_bone: Option<String>,
    /// Cryptographic proof
    pub proof: CollapseProof,
    /// Original query (for reference)
    pub source_query: Option<String>,
    /// Statistics
    pub stats: CollapseStats,
}

impl CollapseResult {
    /// Get number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index
    pub fn get_row(&self, index: usize) -> Option<&CollapsedRow> {
        self.rows.get(index)
    }

    /// Convert to a 2D table (vector of row vectors)
    pub fn to_table(&self) -> Vec<Vec<String>> {
        self.rows.iter()
            .map(|row| row.to_row(&self.columns))
            .collect()
    }

    /// Convert to CSV format
    pub fn to_csv(&self) -> String {
        let mut csv = String::new();

        // Header
        let headers: Vec<String> = self.columns.iter()
            .map(|d| format!("{:?}", d))
            .collect();
        csv.push_str(&headers.join(","));
        csv.push('\n');

        // Rows
        for row in &self.rows {
            let values = row.to_row(&self.columns);
            csv.push_str(&values.join(","));
            csv.push('\n');
        }

        csv
    }

    /// Convert to markdown table
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        let headers: Vec<String> = self.columns.iter()
            .map(|d| format!("{:?}", d))
            .collect();
        md.push_str("| ");
        md.push_str(&headers.join(" | "));
        md.push_str(" |\n");

        // Separator
        md.push_str("|");
        for _ in &self.columns {
            md.push_str("------|");
        }
        md.push('\n');

        // Rows
        for row in &self.rows {
            let values = row.to_row(&self.columns);
            md.push_str("| ");
            md.push_str(&values.join(" | "));
            md.push_str(" |\n");
        }

        md
    }
}

/// Statistics about a collapse operation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollapseStats {
    /// Total concepts searched
    pub concepts_searched: usize,
    /// Concepts after filtering
    pub concepts_filtered: usize,
    /// Unique rows generated
    pub rows_generated: usize,
    /// Dimensions collapsed
    pub dimensions_collapsed: usize,
    /// Dimensions enumerated
    pub dimensions_enumerated: usize,
    /// Average quality score
    pub avg_quality: f32,
    /// Processing time in milliseconds
    pub processing_ms: u64,
}

/// Engine for collapsing 5W queries into tables
pub struct CollapseEngine {
    /// Minimum quality score to include
    quality_threshold: f32,
    /// Maximum rows to return
    max_rows: usize,
    /// Whether to generate BONE from PIN
    generate_bones: bool,
}

impl CollapseEngine {
    /// Create a new collapse engine
    pub fn new() -> Self {
        Self {
            quality_threshold: 0.0,
            max_rows: 1000,
            generate_bones: true,
        }
    }

    /// Set quality threshold
    pub fn with_quality_threshold(mut self, threshold: f32) -> Self {
        self.quality_threshold = threshold;
        self
    }

    /// Set maximum rows
    pub fn with_max_rows(mut self, max: usize) -> Self {
        self.max_rows = max;
        self
    }

    /// Set whether to generate BONEs
    pub fn with_bone_generation(mut self, generate: bool) -> Self {
        self.generate_bones = generate;
        self
    }

    /// Collapse a hyperspace query into a table result
    pub fn collapse(&self, query: &HyperspaceQuery, data: &[CollapsedRow]) -> CollapseResult {
        let start = std::time::Instant::now();

        // Apply filters
        let filtered: Vec<CollapsedRow> = data.iter()
            .filter(|row| self.matches_query(row, query))
            .filter(|row| row.quality_score >= self.quality_threshold)
            .cloned()
            .take(self.max_rows)
            .collect();

        // Generate BONE if we have a PIN
        let new_bone = if self.generate_bones && !query.pin.is_empty() && !filtered.is_empty() {
            Some(self.generate_bone(query, &filtered))
        } else {
            None
        };

        let proof = CollapseProof::new(query, &filtered);
        let avg_quality = if filtered.is_empty() {
            0.0
        } else {
            filtered.iter().map(|r| r.quality_score).sum::<f32>() / filtered.len() as f32
        };

        let stats = CollapseStats {
            concepts_searched: data.len(),
            concepts_filtered: filtered.len(),
            rows_generated: filtered.len(),
            dimensions_collapsed: query.collapse.len(),
            dimensions_enumerated: query.enumerate.len(),
            avg_quality,
            processing_ms: start.elapsed().as_millis() as u64,
        };

        CollapseResult {
            id: Uuid::new_v4(),
            columns: query.enumerate.clone(),
            rows: filtered,
            new_bone,
            proof,
            source_query: query.natural_source.clone(),
            stats,
        }
    }

    /// Check if a row matches the query
    fn matches_query(&self, row: &CollapsedRow, query: &HyperspaceQuery) -> bool {
        // Check pinned dimensions
        for (dim, pin_value) in &query.pin {
            if let Some(row_value) = row.values.get(dim) {
                if row_value != &pin_value.value {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check filters
        for filter in &query.filter {
            if let Some(row_value) = row.values.get(&filter.dimension) {
                if !self.matches_filter(row_value, filter) {
                    return false;
                }
            }
        }

        true
    }

    /// Check if a value matches a filter
    fn matches_filter(&self, value: &str, filter: &DimensionFilter) -> bool {
        // Use the filter's built-in evaluate method
        filter.evaluate(value)
    }

    /// Generate a BONE constraint from a successful PIN
    fn generate_bone(&self, query: &HyperspaceQuery, rows: &[CollapsedRow]) -> String {
        let mut bone_parts = Vec::new();

        // Summary based on PIN
        for (dim, pin_value) in &query.pin {
            bone_parts.push(format!("{:?}={}", dim, pin_value.value));
        }

        // Add row count context
        let count = rows.len();
        let avg_quality = rows.iter().map(|r| r.quality_score).sum::<f32>() / count as f32;

        format!(
            "ESTABLISHED: {} matching entries for [{}], avg quality {:.2}",
            count,
            bone_parts.join(", "),
            avg_quality
        )
    }
}

impl Default for CollapseEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating collapsed rows from various sources
pub struct RowBuilder {
    row: CollapsedRow,
}

impl RowBuilder {
    /// Create a new row builder
    pub fn new() -> Self {
        Self {
            row: CollapsedRow::new(),
        }
    }

    /// Set WHO dimension
    pub fn who(mut self, value: impl Into<String>) -> Self {
        self.row.set(Dimension::Who, value);
        self
    }

    /// Set WHAT dimension
    pub fn what(mut self, value: impl Into<String>) -> Self {
        self.row.set(Dimension::What, value);
        self
    }

    /// Set WHERE dimension
    pub fn r#where(mut self, value: impl Into<String>) -> Self {
        self.row.set(Dimension::Where, value);
        self
    }

    /// Set WHEN dimension
    pub fn when(mut self, value: impl Into<String>) -> Self {
        self.row.set(Dimension::When, value);
        self
    }

    /// Set WHY dimension
    pub fn why(mut self, value: impl Into<String>) -> Self {
        self.row.set(Dimension::Why, value);
        self
    }

    /// Set quality score
    pub fn quality(mut self, score: f32) -> Self {
        self.row.quality_score = score;
        self
    }

    /// Add a source concept
    pub fn source(mut self, concept: ConceptId) -> Self {
        self.row.source_concepts.push(concept);
        self
    }

    /// Build the row
    pub fn build(self) -> CollapsedRow {
        self.row
    }
}

impl Default for RowBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Table output format for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableOutput {
    /// Column names
    pub columns: Vec<String>,
    /// Row data
    pub data: Vec<Vec<String>>,
    /// Total row count
    pub total_rows: usize,
    /// Whether data was truncated
    pub truncated: bool,
}

impl TableOutput {
    /// Create from a collapse result
    pub fn from_collapse(result: &CollapseResult) -> Self {
        let columns: Vec<String> = result.columns.iter()
            .map(|d| format!("{:?}", d))
            .collect();
        let data = result.to_table();

        Self {
            columns,
            total_rows: data.len(),
            data,
            truncated: false,
        }
    }

    /// Create from collapse result with limit
    pub fn from_collapse_limited(result: &CollapseResult, limit: usize) -> Self {
        let columns: Vec<String> = result.columns.iter()
            .map(|d| format!("{:?}", d))
            .collect();
        let full_data = result.to_table();
        let truncated = full_data.len() > limit;
        let data: Vec<Vec<String>> = full_data.into_iter().take(limit).collect();

        Self {
            columns,
            total_rows: result.rows.len(),
            data,
            truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collapsed_row() {
        let mut row = CollapsedRow::new();
        row.set(Dimension::Who, "user_001");
        row.set(Dimension::What, "jwt-validation");
        row.set(Dimension::When, "2025-12-15");
        row.quality_score = 0.85;

        assert_eq!(row.get(Dimension::Who), Some("user_001"));
        assert_eq!(row.get(Dimension::What), Some("jwt-validation"));
        assert_eq!(row.quality_score, 0.85);
    }

    #[test]
    fn test_row_builder() {
        let row = RowBuilder::new()
            .who("alice")
            .what("authentication")
            .r#where("security")
            .when("2025-12-01")
            .why("compliance")
            .quality(0.9)
            .build();

        assert_eq!(row.get(Dimension::Who), Some("alice"));
        assert_eq!(row.get(Dimension::What), Some("authentication"));
        assert_eq!(row.get(Dimension::Where), Some("security"));
        assert_eq!(row.get(Dimension::When), Some("2025-12-01"));
        assert_eq!(row.get(Dimension::Why), Some("compliance"));
        assert_eq!(row.quality_score, 0.9);
    }

    #[test]
    fn test_collapse_engine() {
        let engine = CollapseEngine::new();

        // Create test data
        let data = vec![
            RowBuilder::new()
                .who("user_001")
                .what("jwt-validation")
                .r#where("security")
                .when("2025-12-15")
                .quality(0.85)
                .build(),
            RowBuilder::new()
                .who("user_002")
                .what("auth-middleware")
                .r#where("security")
                .when("2025-12-22")
                .quality(0.75)
                .build(),
            RowBuilder::new()
                .who("user_003")
                .what("logging")
                .r#where("observability")
                .when("2025-12-10")
                .quality(0.8)
                .build(),
        ];

        // Query: PIN WHERE=security, ENUMERATE [WHO, WHAT, WHEN]
        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .pin(Dimension::Where, "security")
            .enumerate_dim(Dimension::Who)
            .enumerate_dim(Dimension::What)
            .enumerate_dim(Dimension::When)
            .build();

        let result = engine.collapse(&query, &data);

        // Should have 2 rows (security only)
        assert_eq!(result.row_count(), 2);
        assert_eq!(result.columns.len(), 3);

        // Should generate a BONE
        assert!(result.new_bone.is_some());
    }

    #[test]
    fn test_collapse_with_filter() {
        let engine = CollapseEngine::new();

        let data = vec![
            RowBuilder::new()
                .who("alice")
                .what("feature-a")
                .when("2025-12-01")
                .quality(0.9)
                .build(),
            RowBuilder::new()
                .who("bob")
                .what("feature-b")
                .when("2025-12-15")
                .quality(0.8)
                .build(),
            RowBuilder::new()
                .who("charlie")
                .what("feature-c")
                .when("2025-12-30")
                .quality(0.7)
                .build(),
        ];

        // Query with WHEN filter
        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .filter_op(Dimension::When, FilterOp::Gte, "2025-12-10".to_string())
            .enumerate_dim(Dimension::Who)
            .enumerate_dim(Dimension::What)
            .build();

        let result = engine.collapse(&query, &data);

        // Should have 2 rows (Dec 15 and Dec 30)
        assert_eq!(result.row_count(), 2);
    }

    #[test]
    fn test_to_csv() {
        let data = vec![
            RowBuilder::new()
                .who("alice")
                .what("task1")
                .quality(0.9)
                .build(),
            RowBuilder::new()
                .who("bob")
                .what("task2")
                .quality(0.8)
                .build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .enumerate_dim(Dimension::Who)
            .enumerate_dim(Dimension::What)
            .build();

        let engine = CollapseEngine::new().with_bone_generation(false);
        let result = engine.collapse(&query, &data);

        let csv = result.to_csv();
        assert!(csv.contains("Who,What"));
        assert!(csv.contains("alice,task1"));
        assert!(csv.contains("bob,task2"));
    }

    #[test]
    fn test_to_markdown() {
        let data = vec![
            RowBuilder::new()
                .who("alice")
                .what("task1")
                .quality(0.9)
                .build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .enumerate_dim(Dimension::Who)
            .enumerate_dim(Dimension::What)
            .build();

        let engine = CollapseEngine::new().with_bone_generation(false);
        let result = engine.collapse(&query, &data);

        let md = result.to_markdown();
        assert!(md.contains("| Who | What |"));
        assert!(md.contains("|------|"));
        assert!(md.contains("| alice | task1 |"));
    }

    #[test]
    fn test_collapse_proof() {
        let data = vec![
            RowBuilder::new()
                .who("test")
                .what("data")
                .quality(0.8)
                .build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .pin(Dimension::Who, "test")
            .enumerate_dim(Dimension::What)
            .build();

        let engine = CollapseEngine::new();
        let result = engine.collapse(&query, &data);

        // Verify the proof
        assert!(result.proof.verify(&result.rows));
        assert_eq!(result.proof.row_count, 1);
    }

    #[test]
    fn test_quality_threshold() {
        let data = vec![
            RowBuilder::new().who("a").quality(0.9).build(),
            RowBuilder::new().who("b").quality(0.5).build(),
            RowBuilder::new().who("c").quality(0.3).build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .enumerate_dim(Dimension::Who)
            .build();

        let engine = CollapseEngine::new().with_quality_threshold(0.7);
        let result = engine.collapse(&query, &data);

        // Should only have 1 row (quality >= 0.7)
        assert_eq!(result.row_count(), 1);
        assert_eq!(result.rows[0].get(Dimension::Who), Some("a"));
    }

    #[test]
    fn test_table_output() {
        let data = vec![
            RowBuilder::new()
                .who("user1")
                .what("action1")
                .quality(0.8)
                .build(),
            RowBuilder::new()
                .who("user2")
                .what("action2")
                .quality(0.9)
                .build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .enumerate_dim(Dimension::Who)
            .enumerate_dim(Dimension::What)
            .build();

        let engine = CollapseEngine::new().with_bone_generation(false);
        let result = engine.collapse(&query, &data);
        let table = TableOutput::from_collapse(&result);

        assert_eq!(table.columns, vec!["Who", "What"]);
        assert_eq!(table.total_rows, 2);
        assert!(!table.truncated);
    }

    #[test]
    fn test_stats() {
        let data = vec![
            RowBuilder::new().who("a").r#where("x").quality(0.8).build(),
            RowBuilder::new().who("b").r#where("x").quality(0.6).build(),
            RowBuilder::new().who("c").r#where("y").quality(0.9).build(),
        ];

        let query = crate::hyperspace::HyperspaceQueryBuilder::new()
            .pin(Dimension::Where, "x")
            .enumerate_dim(Dimension::Who)
            .collapse_dim(Dimension::Where)
            .build();

        let engine = CollapseEngine::new();
        let result = engine.collapse(&query, &data);

        assert_eq!(result.stats.concepts_searched, 3);
        assert_eq!(result.stats.concepts_filtered, 2);
        assert_eq!(result.stats.dimensions_collapsed, 1);
        assert_eq!(result.stats.dimensions_enumerated, 1);
        assert!((result.stats.avg_quality - 0.7).abs() < 0.01);
    }
}
