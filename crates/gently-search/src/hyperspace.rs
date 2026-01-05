//! 5W Hyperspace - Multi-dimensional knowledge topology
//!
//! Alexandria operates in five semantic dimensions derived from journalism's
//! fundamental questions: WHO, WHAT, WHERE, WHEN, WHY
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                 5W HYPERSPACE                       │
//! │                                                     │
//! │  WHO   → Agent/Entity dimension (Tesseract Observer)│
//! │  WHAT  → Content/Action dimension (Tesseract Actual)│
//! │  WHERE → Domain/Location dimension (Tesseract Context)│
//! │  WHEN  → Temporal/Sequence dimension (Tesseract Temporal)│
//! │  WHY   → Causal/Reason dimension (Tesseract Purpose)│
//! │                                                     │
//! │  Each knowledge node exists at coordinates          │
//! │  in this 5-dimensional space.                       │
//! └─────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use regex::Regex;

use gently_alexandria::ConceptId;

/// The 5W dimensions of knowledge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dimension {
    /// WHO - Agent/Entity dimension (Tesseract Observer face)
    Who,
    /// WHAT - Content/Action dimension (Tesseract Actual face)
    What,
    /// WHERE - Domain/Location dimension (Tesseract Context face)
    Where,
    /// WHEN - Temporal/Sequence dimension (Tesseract Temporal face)
    When,
    /// WHY - Causal/Reason dimension (Tesseract Purpose face)
    Why,
}

impl Dimension {
    /// Get all dimensions
    pub fn all() -> &'static [Dimension] {
        &[
            Dimension::Who,
            Dimension::What,
            Dimension::Where,
            Dimension::When,
            Dimension::Why,
        ]
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Dimension::Who => "WHO",
            Dimension::What => "WHAT",
            Dimension::Where => "WHERE",
            Dimension::When => "WHEN",
            Dimension::Why => "WHY",
        }
    }

    /// Get question form
    pub fn question(&self) -> &'static str {
        match self {
            Dimension::Who => "Who?",
            Dimension::What => "What?",
            Dimension::Where => "Where?",
            Dimension::When => "When?",
            Dimension::Why => "Why?",
        }
    }

    /// Map to Tesseract face index
    pub fn tesseract_face(&self) -> usize {
        match self {
            Dimension::Who => 4,    // Observer face
            Dimension::What => 0,   // Actual face
            Dimension::Where => 5,  // Context face
            Dimension::When => 3,   // Temporal face
            Dimension::Why => 7,    // Purpose face
        }
    }
}

impl std::fmt::Display for Dimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A value in a dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionValue {
    /// The raw value
    pub value: String,
    /// Associated concepts (if resolved)
    pub concepts: Vec<ConceptId>,
    /// Confidence of extraction (0.0-1.0)
    pub confidence: f32,
}

impl DimensionValue {
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
            concepts: Vec::new(),
            confidence: 1.0,
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_concepts(mut self, concepts: Vec<ConceptId>) -> Self {
        self.concepts = concepts;
        self
    }
}

/// Filter operations for dimensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOp {
    /// Equals
    Eq,
    /// Not equals
    Ne,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Greater than or equal
    Gte,
    /// Less than or equal
    Lte,
    /// In set
    In,
    /// Contains (substring)
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Matches regex
    Matches,
}

/// Filter value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterValue {
    /// Single string value
    String(String),
    /// Multiple string values (for In operation)
    StringList(Vec<String>),
    /// Date/time value
    DateTime(DateTime<Utc>),
    /// Date range
    DateRange { from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>> },
    /// Numeric value
    Number(f64),
    /// Numeric range
    NumberRange { from: Option<f64>, to: Option<f64> },
}

/// A filter on a dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionFilter {
    /// The dimension being filtered
    pub dimension: Dimension,
    /// Filter operation
    pub operator: FilterOp,
    /// Filter value
    pub value: FilterValue,
}

impl DimensionFilter {
    pub fn eq(dimension: Dimension, value: &str) -> Self {
        Self {
            dimension,
            operator: FilterOp::Eq,
            value: FilterValue::String(value.to_string()),
        }
    }

    pub fn contains(dimension: Dimension, value: &str) -> Self {
        Self {
            dimension,
            operator: FilterOp::Contains,
            value: FilterValue::String(value.to_string()),
        }
    }

    pub fn date_range(dimension: Dimension, from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> Self {
        Self {
            dimension,
            operator: FilterOp::Gte, // Simplified - actual comparison in evaluate
            value: FilterValue::DateRange { from, to },
        }
    }

    pub fn in_list(dimension: Dimension, values: Vec<String>) -> Self {
        Self {
            dimension,
            operator: FilterOp::In,
            value: FilterValue::StringList(values),
        }
    }

    /// Evaluate this filter against a value
    pub fn evaluate(&self, value: &str) -> bool {
        match (&self.operator, &self.value) {
            (FilterOp::Eq, FilterValue::String(v)) => value == v,
            (FilterOp::Ne, FilterValue::String(v)) => value != v,
            (FilterOp::Gt, FilterValue::String(v)) => value > v.as_str(),
            (FilterOp::Lt, FilterValue::String(v)) => value < v.as_str(),
            (FilterOp::Gte, FilterValue::String(v)) => value >= v.as_str(),
            (FilterOp::Lte, FilterValue::String(v)) => value <= v.as_str(),
            (FilterOp::Contains, FilterValue::String(v)) => value.to_lowercase().contains(&v.to_lowercase()),
            (FilterOp::StartsWith, FilterValue::String(v)) => value.to_lowercase().starts_with(&v.to_lowercase()),
            (FilterOp::EndsWith, FilterValue::String(v)) => value.to_lowercase().ends_with(&v.to_lowercase()),
            (FilterOp::In, FilterValue::StringList(list)) => list.iter().any(|v| v.to_lowercase() == value.to_lowercase()),
            (FilterOp::Matches, FilterValue::String(pattern)) => {
                Regex::new(pattern).map(|r| r.is_match(value)).unwrap_or(false)
            }
            _ => true, // Default pass for unhandled combinations
        }
    }
}

/// A hyperspace query across 5W dimensions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HyperspaceQuery {
    /// Pinned dimensions (fixed values that constrain the query)
    pub pin: HashMap<Dimension, DimensionValue>,
    /// Filtered dimensions (range/condition filters)
    pub filter: Vec<DimensionFilter>,
    /// Collapsed dimensions (removed from output, aggregated)
    pub collapse: Vec<Dimension>,
    /// Enumerated dimensions (become columns in output)
    pub enumerate: Vec<Dimension>,
    /// Natural language source (if extracted from NL)
    pub natural_source: Option<String>,
    /// Maximum results
    pub limit: usize,
}

impl HyperspaceQuery {
    /// Create a new query
    pub fn new() -> Self {
        Self {
            pin: HashMap::new(),
            filter: Vec::new(),
            collapse: Vec::new(),
            enumerate: Vec::new(),
            natural_source: None,
            limit: 100,
        }
    }

    /// Create from natural language
    pub fn from_natural(query: &str) -> Self {
        let extractor = NaturalLanguageExtractor::new();
        extractor.extract(query)
    }

    /// Pin a dimension to a value
    pub fn pin_dimension(mut self, dim: Dimension, value: &str) -> Self {
        self.pin.insert(dim, DimensionValue::new(value));
        self
    }

    /// Add a filter
    pub fn add_filter(mut self, filter: DimensionFilter) -> Self {
        self.filter.push(filter);
        self
    }

    /// Mark dimensions to collapse (not in output)
    pub fn collapse_dimensions(mut self, dims: Vec<Dimension>) -> Self {
        self.collapse = dims;
        self
    }

    /// Mark dimensions to enumerate (become columns)
    pub fn enumerate_dimensions(mut self, dims: Vec<Dimension>) -> Self {
        self.enumerate = dims;
        self
    }

    /// Set result limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Get all dimensions that should appear in output
    pub fn output_dimensions(&self) -> Vec<Dimension> {
        if !self.enumerate.is_empty() {
            return self.enumerate.clone();
        }

        // Default: all non-pinned, non-collapsed dimensions
        Dimension::all()
            .iter()
            .filter(|d| !self.pin.contains_key(d) && !self.collapse.contains(d))
            .copied()
            .collect()
    }

    /// Check if a dimension is constrained (pinned or filtered)
    pub fn is_constrained(&self, dim: Dimension) -> bool {
        self.pin.contains_key(&dim) || self.filter.iter().any(|f| f.dimension == dim)
    }
}

/// Builder pattern for HyperspaceQuery
pub struct HyperspaceQueryBuilder {
    query: HyperspaceQuery,
}

impl HyperspaceQueryBuilder {
    pub fn new() -> Self {
        Self {
            query: HyperspaceQuery::new(),
        }
    }

    pub fn who(mut self, value: &str) -> Self {
        self.query.pin.insert(Dimension::Who, DimensionValue::new(value));
        self
    }

    pub fn what(mut self, value: &str) -> Self {
        self.query.pin.insert(Dimension::What, DimensionValue::new(value));
        self
    }

    pub fn where_dim(mut self, value: &str) -> Self {
        self.query.pin.insert(Dimension::Where, DimensionValue::new(value));
        self
    }

    pub fn when(mut self, value: &str) -> Self {
        self.query.pin.insert(Dimension::When, DimensionValue::new(value));
        self
    }

    pub fn why(mut self, value: &str) -> Self {
        self.query.pin.insert(Dimension::Why, DimensionValue::new(value));
        self
    }

    pub fn when_range(mut self, from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> Self {
        self.query.filter.push(DimensionFilter::date_range(Dimension::When, from, to));
        self
    }

    pub fn filter(mut self, filter: DimensionFilter) -> Self {
        self.query.filter.push(filter);
        self
    }

    pub fn collapse(mut self, dims: Vec<Dimension>) -> Self {
        self.query.collapse = dims;
        self
    }

    pub fn enumerate(mut self, dims: Vec<Dimension>) -> Self {
        self.query.enumerate = dims;
        self
    }

    /// Add a single dimension to enumerate
    pub fn enumerate_dim(mut self, dim: Dimension) -> Self {
        self.query.enumerate.push(dim);
        self
    }

    /// Add a single dimension to collapse
    pub fn collapse_dim(mut self, dim: Dimension) -> Self {
        self.query.collapse.push(dim);
        self
    }

    /// Pin a dimension with a string value
    pub fn pin(mut self, dim: Dimension, value: &str) -> Self {
        self.query.pin.insert(dim, DimensionValue::new(value));
        self
    }

    /// Add a filter with operator and string value
    pub fn filter_op(mut self, dim: Dimension, op: FilterOp, value: String) -> Self {
        self.query.filter.push(DimensionFilter {
            dimension: dim,
            operator: op,
            value: FilterValue::String(value),
        });
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.query.limit = n;
        self
    }

    pub fn build(self) -> HyperspaceQuery {
        self.query
    }
}

impl Default for HyperspaceQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts 5W dimensions from natural language queries
pub struct NaturalLanguageExtractor {
    /// WHO indicators
    who_patterns: Vec<&'static str>,
    /// WHAT indicators
    what_patterns: Vec<&'static str>,
    /// WHERE indicators
    where_patterns: Vec<&'static str>,
    /// WHEN indicators
    when_patterns: Vec<&'static str>,
    /// WHY indicators
    why_patterns: Vec<&'static str>,
    /// Intent indicators (for WHAT dimension)
    intent_keywords: Vec<(&'static str, &'static str)>,
    /// Temporal keywords
    temporal_keywords: Vec<(&'static str, i64)>, // (keyword, days_offset)
}

impl NaturalLanguageExtractor {
    pub fn new() -> Self {
        Self {
            who_patterns: vec![
                "who ", "user ", "developer ", "admin ", "team ", "person ",
                "by ", "from ", "author ", "owner ", "created by ",
            ],
            what_patterns: vec![
                "what ", "which ", "the ", "a ", "an ", "find ", "show ",
                "list ", "get ", "search ", "query ",
            ],
            where_patterns: vec![
                "in ", "at ", "within ", "inside ", "from ", "domain ",
                "module ", "file ", "directory ", "folder ", "area ",
                "security", "auth", "database", "network", "api", "frontend", "backend",
            ],
            when_patterns: vec![
                "when ", "since ", "after ", "before ", "during ", "between ",
                "today", "yesterday", "last week", "last month", "this year",
            ],
            why_patterns: vec![
                "why ", "because ", "due to ", "caused by ", "reason ",
                "broke", "failed", "error", "bug", "issue", "problem",
                "success", "fixed", "resolved", "completed",
            ],
            intent_keywords: vec![
                ("fix", "fix"),
                ("broke", "failure"),
                ("error", "error"),
                ("bug", "bug"),
                ("fail", "failure"),
                ("success", "success"),
                ("build", "build"),
                ("create", "create"),
                ("delete", "delete"),
                ("update", "update"),
            ],
            temporal_keywords: vec![
                ("today", 0),
                ("yesterday", -1),
                ("last week", -7),
                ("this week", -7),
                ("last month", -30),
                ("this month", -30),
                ("last year", -365),
                ("this year", -365),
            ],
        }
    }

    /// Extract 5W dimensions from natural language query
    pub fn extract(&self, query: &str) -> HyperspaceQuery {
        let lower = query.to_lowercase();
        let mut result = HyperspaceQuery::new();
        result.natural_source = Some(query.to_string());

        // Extract WHERE (domain/location)
        for pattern in &self.where_patterns {
            if lower.contains(pattern) {
                if let Some(value) = self.extract_value_after(&lower, pattern) {
                    result.pin.insert(
                        Dimension::Where,
                        DimensionValue::new(&value).with_confidence(0.7),
                    );
                    break;
                }
                // Check if pattern itself is the domain (like "security")
                if !pattern.ends_with(' ') && lower.contains(pattern) {
                    result.pin.insert(
                        Dimension::Where,
                        DimensionValue::new(pattern.trim()).with_confidence(0.8),
                    );
                }
            }
        }

        // Extract WHY (reason/cause)
        for pattern in &self.why_patterns {
            if lower.contains(pattern) {
                // Use the pattern itself as the WHY value
                result.pin.insert(
                    Dimension::Why,
                    DimensionValue::new(pattern.trim()).with_confidence(0.6),
                );
                break;
            }
        }

        // Extract WHEN (temporal)
        for (keyword, days_offset) in &self.temporal_keywords {
            if lower.contains(keyword) {
                let from = Utc::now() + chrono::Duration::days(*days_offset);
                result.filter.push(DimensionFilter::date_range(
                    Dimension::When,
                    Some(from),
                    None,
                ));
                break;
            }
        }

        // Check for specific date patterns (e.g., "since December", "after January")
        if let Some(month_filter) = self.extract_month_filter(&lower) {
            result.filter.push(month_filter);
        }

        // Determine what to enumerate vs collapse based on query type
        self.infer_output_structure(&lower, &mut result);

        result
    }

    fn extract_value_after(&self, text: &str, pattern: &str) -> Option<String> {
        if let Some(pos) = text.find(pattern) {
            let after = &text[pos + pattern.len()..];
            let words: Vec<&str> = after.split_whitespace().collect();
            if !words.is_empty() {
                return Some(words[0].to_string());
            }
        }
        None
    }

    fn extract_month_filter(&self, text: &str) -> Option<DimensionFilter> {
        let months = [
            ("january", 1), ("february", 2), ("march", 3), ("april", 4),
            ("may", 5), ("june", 6), ("july", 7), ("august", 8),
            ("september", 9), ("october", 10), ("november", 11), ("december", 12),
            ("jan", 1), ("feb", 2), ("mar", 3), ("apr", 4),
            ("jun", 6), ("jul", 7), ("aug", 8), ("sep", 9),
            ("oct", 10), ("nov", 11), ("dec", 12),
        ];

        for (name, month) in months.iter() {
            if text.contains(name) {
                // Determine year (current or previous based on whether month has passed)
                let now = Utc::now();
                let current_month = now.format("%m").to_string().parse::<u32>().unwrap_or(1);
                let year = if *month as u32 > current_month {
                    now.format("%Y").to_string().parse::<i32>().unwrap_or(2026) - 1
                } else {
                    now.format("%Y").to_string().parse::<i32>().unwrap_or(2026)
                };

                // Create date from first of that month
                let from_str = format!("{}-{:02}-01T00:00:00Z", year, month);
                if let Ok(from) = from_str.parse::<DateTime<Utc>>() {
                    return Some(DimensionFilter::date_range(Dimension::When, Some(from), None));
                }
            }
        }
        None
    }

    fn infer_output_structure(&self, text: &str, query: &mut HyperspaceQuery) {
        // If asking "what", enumerate WHAT
        if text.starts_with("what ") || text.contains("show ") || text.contains("list ") {
            // Pinned dimensions get collapsed, rest enumerated
            let pinned: Vec<Dimension> = query.pin.keys().copied().collect();
            query.collapse = pinned;

            // Enumerate remaining dimensions
            let enumerated: Vec<Dimension> = Dimension::all()
                .iter()
                .filter(|d| !query.pin.contains_key(d))
                .copied()
                .collect();

            // If enumerated is too many, default to WHO, WHAT, WHEN
            if enumerated.len() > 3 {
                query.enumerate = vec![Dimension::Who, Dimension::What, Dimension::When];
            } else {
                query.enumerate = enumerated;
            }
        } else if text.contains("how many") || text.contains("count") {
            // Aggregation query - collapse everything except what's being counted
            query.collapse = vec![Dimension::Who, Dimension::When, Dimension::Why];
            query.enumerate = vec![Dimension::What];
        }
    }
}

impl Default for NaturalLanguageExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a hyperspace query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperspaceResult {
    /// The original query
    pub query: HyperspaceQuery,
    /// Matched items
    pub items: Vec<HyperspaceItem>,
    /// Total count before limit
    pub total_count: usize,
    /// Execution stats
    pub stats: HyperspaceStats,
}

/// A single item in hyperspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperspaceItem {
    /// Values for each dimension
    pub dimensions: HashMap<Dimension, String>,
    /// Source concept IDs
    pub concepts: Vec<ConceptId>,
    /// Quality score (from inference)
    pub quality: f32,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl HyperspaceItem {
    /// Get value for a dimension
    pub fn get(&self, dim: Dimension) -> Option<&str> {
        self.dimensions.get(&dim).map(|s| s.as_str())
    }
}

/// Statistics from hyperspace query execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HyperspaceStats {
    /// Dimensions pinned
    pub pinned_dimensions: usize,
    /// Filters applied
    pub filters_applied: usize,
    /// Items before filtering
    pub items_before_filter: usize,
    /// Items after filtering
    pub items_after_filter: usize,
    /// Execution time in ms
    pub execution_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dimension_properties() {
        assert_eq!(Dimension::Who.name(), "WHO");
        assert_eq!(Dimension::What.tesseract_face(), 0);
        assert_eq!(Dimension::Where.tesseract_face(), 5);
    }

    #[test]
    fn test_query_builder() {
        let query = HyperspaceQueryBuilder::new()
            .where_dim("security")
            .why("failure")
            .enumerate(vec![Dimension::Who, Dimension::What, Dimension::When])
            .collapse(vec![Dimension::Where, Dimension::Why])
            .build();

        assert!(query.pin.contains_key(&Dimension::Where));
        assert!(query.pin.contains_key(&Dimension::Why));
        assert_eq!(query.enumerate.len(), 3);
        assert_eq!(query.collapse.len(), 2);
    }

    #[test]
    fn test_natural_language_extraction() {
        let extractor = NaturalLanguageExtractor::new();

        let query = extractor.extract("What broke in security since December?");

        // Should pin WHERE to security
        assert!(query.pin.get(&Dimension::Where).is_some());

        // Should pin WHY to broke/failure
        assert!(query.pin.get(&Dimension::Why).is_some());

        // Should have temporal filter
        assert!(!query.filter.is_empty());
    }

    #[test]
    fn test_filter_evaluation() {
        let filter = DimensionFilter::contains(Dimension::What, "auth");
        assert!(filter.evaluate("authentication"));
        assert!(filter.evaluate("auth-middleware"));
        assert!(!filter.evaluate("database"));

        let filter_eq = DimensionFilter::eq(Dimension::Where, "security");
        assert!(filter_eq.evaluate("security"));
        assert!(!filter_eq.evaluate("database"));
    }

    #[test]
    fn test_output_dimensions() {
        let query = HyperspaceQueryBuilder::new()
            .where_dim("security")
            .collapse(vec![Dimension::Where])
            .enumerate(vec![Dimension::Who, Dimension::What])
            .build();

        let output = query.output_dimensions();
        assert_eq!(output.len(), 2);
        assert!(output.contains(&Dimension::Who));
        assert!(output.contains(&Dimension::What));
    }

    #[test]
    fn test_dimension_value() {
        let val = DimensionValue::new("security")
            .with_confidence(0.9)
            .with_concepts(vec![ConceptId::from_concept("test")]);

        assert_eq!(val.value, "security");
        assert_eq!(val.confidence, 0.9);
        assert_eq!(val.concepts.len(), 1);
    }
}
