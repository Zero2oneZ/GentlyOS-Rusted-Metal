//! # Pre-Optimization - CIRCLE/PIN Pipeline
//!
//! Before sending to expensive big compute (Claude):
//!
//! 1. TINY LLM A (CIRCLE - Eliminator): "What is this query DEFINITELY NOT about?"
//! 2. TINY LLM B (PIN - Contextualizer): "What local context is relevant?"
//! 3. PROMPT BUILDER: Assemble optimized prompt with context
//!
//! Result: 10x more efficient prompt (cost: 10 credits instead of 100)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::idea_extract::Idea;
use crate::relationships::EntityId;
use crate::MicroConfig;

/// Result of elimination (CIRCLE phase)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EliminationResult {
    /// What domains to exclude
    pub excluded_domains: Vec<String>,
    /// Keywords that are NOT relevant
    pub excluded_keywords: Vec<String>,
    /// Confidence in elimination
    pub confidence: f32,
    /// Reduction ratio (how much search space eliminated)
    pub reduction_ratio: f32,
}

impl EliminationResult {
    /// Create a new elimination result
    pub fn new(
        excluded_domains: Vec<String>,
        excluded_keywords: Vec<String>,
        confidence: f32,
    ) -> Self {
        let reduction = (excluded_domains.len() + excluded_keywords.len()) as f32 * 0.05;
        Self {
            excluded_domains,
            excluded_keywords,
            confidence: confidence.clamp(0.0, 1.0),
            reduction_ratio: reduction.clamp(0.0, 0.9),
        }
    }

    /// Is this domain excluded?
    pub fn is_domain_excluded(&self, domain: &str) -> bool {
        self.excluded_domains.iter().any(|d| d == domain)
    }

    /// Is this keyword excluded?
    pub fn is_keyword_excluded(&self, keyword: &str) -> bool {
        let keyword_lower = keyword.to_lowercase();
        self.excluded_keywords.iter().any(|k| k.to_lowercase() == keyword_lower)
    }

    /// To CIRCLE constraint format
    pub fn to_constraints(&self) -> Vec<String> {
        let mut constraints = Vec::new();
        for domain in &self.excluded_domains {
            constraints.push(format!("NOT domain:{}", domain));
        }
        for kw in &self.excluded_keywords {
            constraints.push(format!("NOT keyword:{}", kw));
        }
        constraints
    }
}

/// Result of contextualization (PIN phase)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextResult {
    /// Relevant file paths
    pub relevant_files: Vec<String>,
    /// Relevant past chats
    pub relevant_chats: Vec<String>,
    /// BONEs to include
    pub bones: Vec<String>,
    /// Keywords that ARE relevant
    pub relevant_keywords: Vec<String>,
    /// Domain(s) this likely belongs to
    pub domains: Vec<String>,
    /// Confidence
    pub confidence: f32,
}

impl ContextResult {
    /// Create a new context result
    pub fn new() -> Self {
        Self {
            relevant_files: Vec::new(),
            relevant_chats: Vec::new(),
            bones: Vec::new(),
            relevant_keywords: Vec::new(),
            domains: Vec::new(),
            confidence: 0.5,
        }
    }

    /// Add a relevant file
    pub fn add_file(&mut self, path: &str) {
        if !self.relevant_files.contains(&path.to_string()) {
            self.relevant_files.push(path.to_string());
        }
    }

    /// Add a BONE constraint
    pub fn add_bone(&mut self, bone: &str) {
        if !self.bones.contains(&bone.to_string()) {
            self.bones.push(bone.to_string());
        }
    }

    /// Add a relevant keyword
    pub fn add_keyword(&mut self, keyword: &str) {
        let kw = keyword.to_lowercase();
        if !self.relevant_keywords.contains(&kw) {
            self.relevant_keywords.push(kw);
        }
    }

    /// Total context items
    pub fn context_count(&self) -> usize {
        self.relevant_files.len()
            + self.relevant_chats.len()
            + self.bones.len()
    }
}

impl Default for ContextResult {
    fn default() -> Self {
        Self::new()
    }
}

/// The optimized prompt ready for big compute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedPrompt {
    /// Original query
    pub original: String,
    /// Optimized query (may be rephrased)
    pub optimized: String,
    /// Context section
    pub context: String,
    /// BONE constraints section
    pub bones_section: String,
    /// NOT (elimination) section
    pub not_section: String,
    /// Expected output format
    pub output_format: String,
    /// Full assembled prompt
    pub full_prompt: String,
    /// Estimated cost reduction (0-1)
    pub cost_reduction: f32,
    /// Pre-processing stats
    pub stats: PreOptStats,
}

impl OptimizedPrompt {
    /// Get estimated token count
    pub fn estimated_tokens(&self) -> usize {
        // Rough estimate: 4 chars per token
        self.full_prompt.len() / 4
    }

    /// Is this prompt well-optimized?
    pub fn is_well_optimized(&self) -> bool {
        self.stats.elimination_ratio > 0.3
            && self.stats.context_relevance > 0.5
    }
}

/// Statistics from pre-optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreOptStats {
    /// How much of search space eliminated
    pub elimination_ratio: f32,
    /// How relevant is attached context
    pub context_relevance: f32,
    /// Number of BONEs attached
    pub bones_count: usize,
    /// Number of files attached
    pub files_count: usize,
    /// Processing time (ms)
    pub processing_ms: u64,
}

/// The pre-optimizer engine
pub struct PreOptimizer {
    /// Known domains
    all_domains: Vec<String>,
    /// Domain keywords mapping
    domain_keywords: std::collections::HashMap<String, Vec<String>>,
    /// Quality threshold
    quality_threshold: f32,
}

impl PreOptimizer {
    /// Create a new pre-optimizer
    pub fn new(config: &MicroConfig) -> Self {
        let mut domain_keywords = std::collections::HashMap::new();

        // Security domain
        domain_keywords.insert(
            "security".to_string(),
            vec![
                "auth", "jwt", "token", "password", "encrypt", "decrypt", "hash",
                "signature", "certificate", "tls", "ssl", "attack", "vulnerability",
                "exploit", "xss", "sql injection", "csrf", "fafo",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        // Database domain
        domain_keywords.insert(
            "database".to_string(),
            vec![
                "sql", "query", "table", "row", "column", "index", "join",
                "select", "insert", "update", "delete", "postgres", "mysql",
                "sqlite", "mongo", "redis",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        // Network domain
        domain_keywords.insert(
            "network".to_string(),
            vec![
                "http", "https", "tcp", "udp", "socket", "request", "response",
                "api", "rest", "graphql", "websocket", "dns", "ip", "port",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        // UI domain
        domain_keywords.insert(
            "ui".to_string(),
            vec![
                "frontend", "component", "render", "button", "form", "input",
                "css", "style", "layout", "responsive", "react", "vue", "html",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        // AI domain
        domain_keywords.insert(
            "ai".to_string(),
            vec![
                "model", "inference", "training", "embedding", "vector", "llm",
                "transformer", "attention", "neural", "prompt", "completion",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        // Crypto domain
        domain_keywords.insert(
            "crypto".to_string(),
            vec![
                "blockchain", "bitcoin", "ethereum", "solana", "wallet", "token",
                "mint", "nft", "defi", "smart contract", "transaction",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        let all_domains = domain_keywords.keys().cloned().collect();

        Self {
            all_domains,
            domain_keywords,
            quality_threshold: config.quality_threshold,
        }
    }

    /// Run full optimization pipeline
    pub fn optimize(
        &self,
        query: &str,
        context: Option<&str>,
        related: &[(EntityId, f32)],
    ) -> crate::Result<OptimizedPrompt> {
        let start = std::time::Instant::now();

        // Phase 1: CIRCLE - Elimination
        let elimination = self.eliminate(query);

        // Phase 2: PIN - Contextualization
        let mut context_result = self.contextualize(query, related);

        // Add any provided context
        if let Some(ctx) = context {
            context_result.relevant_chats.push(ctx.to_string());
        }

        // Phase 3: Build optimized prompt
        let optimized_prompt = self.build_prompt(query, &elimination, &context_result);

        let processing_ms = start.elapsed().as_millis() as u64;

        let stats = PreOptStats {
            elimination_ratio: elimination.reduction_ratio,
            context_relevance: context_result.confidence,
            bones_count: context_result.bones.len(),
            files_count: context_result.relevant_files.len(),
            processing_ms,
        };

        Ok(OptimizedPrompt {
            original: query.to_string(),
            optimized: optimized_prompt.clone(),
            context: context_result.relevant_files.join(", "),
            bones_section: context_result.bones.join("\n"),
            not_section: elimination.to_constraints().join("\n"),
            output_format: "structured".to_string(),
            full_prompt: optimized_prompt,
            cost_reduction: elimination.reduction_ratio * 0.5 + context_result.confidence * 0.3,
            stats,
        })
    }

    /// Phase 1: CIRCLE - Elimination
    /// "What is this query DEFINITELY NOT about?"
    fn eliminate(&self, query: &str) -> EliminationResult {
        let query_lower = query.to_lowercase();
        let _query_words: HashSet<&str> = query_lower.split_whitespace().collect();

        let mut excluded_domains = Vec::new();
        let mut matched_domains = Vec::new();

        // Find domains that ARE relevant
        for (domain, keywords) in &self.domain_keywords {
            let mut matches = 0;
            for keyword in keywords {
                if query_lower.contains(keyword) {
                    matches += 1;
                }
            }
            if matches > 0 {
                matched_domains.push(domain.clone());
            }
        }

        // Exclude domains that are NOT relevant
        for domain in &self.all_domains {
            if !matched_domains.contains(domain) {
                excluded_domains.push(domain.clone());
            }
        }

        // Find common words that are definitely not relevant
        let excluded_keywords = vec![
            // If query mentions rust, exclude python-specific stuff
            if query_lower.contains("rust") && !query_lower.contains("python") {
                vec!["pip", "virtualenv", "django", "flask"]
            } else if query_lower.contains("python") && !query_lower.contains("rust") {
                vec!["cargo", "crate", "trait", "borrow"]
            } else {
                vec![]
            },
        ]
        .into_iter()
        .flatten()
        .map(String::from)
        .collect();

        let confidence = if matched_domains.is_empty() {
            0.3 // Low confidence if we couldn't identify any domain
        } else {
            0.7 + (matched_domains.len() as f32 * 0.05).min(0.25)
        };

        EliminationResult::new(excluded_domains, excluded_keywords, confidence)
    }

    /// Phase 2: PIN - Contextualization
    /// "What local context is relevant?"
    fn contextualize(
        &self,
        query: &str,
        related: &[(EntityId, f32)],
    ) -> ContextResult {
        let query_lower = query.to_lowercase();
        let mut result = ContextResult::new();

        // Identify domains
        for (domain, keywords) in &self.domain_keywords {
            for keyword in keywords {
                if query_lower.contains(keyword) {
                    if !result.domains.contains(domain) {
                        result.domains.push(domain.clone());
                    }
                    result.add_keyword(keyword);
                }
            }
        }

        // Add related entities as context
        for (entity_id, score) in related {
            if *score > self.quality_threshold {
                let id_str = entity_id.as_str();
                if id_str.starts_with("path:") {
                    result.add_file(&id_str[5..]);
                } else if id_str.starts_with("chat:") {
                    result.relevant_chats.push(id_str[5..].to_string());
                }
            }
        }

        // Extract implicit BONEs from query
        if query_lower.contains("must") || query_lower.contains("always") {
            // Extract the constraint
            if let Some(pos) = query_lower.find("must") {
                let constraint = &query[pos..].chars().take(50).collect::<String>();
                result.add_bone(&format!("CONSTRAINT: {}", constraint));
            }
        }

        // Add default BONEs based on domain
        let domains = result.domains.clone();
        for domain in &domains {
            match domain.as_str() {
                "security" => {
                    result.add_bone("Always validate input");
                    result.add_bone("Never store secrets in plaintext");
                }
                "database" => {
                    result.add_bone("Use parameterized queries");
                }
                "network" => {
                    result.add_bone("Handle connection timeouts");
                }
                _ => {}
            }
        }

        // Calculate confidence based on context quality
        result.confidence = if result.context_count() > 0 {
            0.5 + (result.context_count() as f32 * 0.1).min(0.4)
        } else {
            0.3
        };

        result
    }

    /// Phase 3: Build the optimized prompt
    fn build_prompt(
        &self,
        query: &str,
        elimination: &EliminationResult,
        context: &ContextResult,
    ) -> String {
        let mut parts = Vec::new();

        // Original query
        parts.push(query.to_string());

        // Context section
        if !context.relevant_files.is_empty() {
            parts.push(format!(
                "\n\nCONTEXT FILES:\n{}",
                context.relevant_files.join("\n")
            ));
        }

        // BONEs section
        if !context.bones.is_empty() {
            parts.push(format!(
                "\n\nCONSTRAINTS (BONES):\n{}",
                context.bones.join("\n")
            ));
        }

        // NOT section
        if !elimination.excluded_domains.is_empty() {
            parts.push(format!(
                "\n\nNOT ABOUT:\n- Domains: {}\n- Keywords: {}",
                elimination.excluded_domains.join(", "),
                elimination.excluded_keywords.join(", ")
            ));
        }

        // Domain hint
        if !context.domains.is_empty() {
            parts.push(format!(
                "\n\nDOMAIN: {}",
                context.domains.join(", ")
            ));
        }

        // Output format hint
        parts.push("\n\nOUTPUT: Provide a specific, actionable answer.".to_string());

        parts.join("")
    }

    /// Optimize ideas for storage (filter and enrich)
    pub fn optimize_ideas(&self, ideas: &[Idea]) -> Vec<Idea> {
        ideas
            .iter()
            .filter(|i| i.importance() > self.quality_threshold)
            .cloned()
            .collect()
    }

    /// Quick check: does this query need big compute?
    pub fn needs_big_compute(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();

        // Complex queries need big compute
        let complexity_indicators = [
            "design", "architect", "implement", "create", "build",
            "complex", "system", "distributed", "optimize", "refactor",
        ];

        let mut complexity_score = 0;
        for indicator in &complexity_indicators {
            if query_lower.contains(indicator) {
                complexity_score += 1;
            }
        }

        // Length also indicates complexity
        if query.len() > 500 {
            complexity_score += 2;
        }

        complexity_score >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elimination() {
        let config = MicroConfig::default();
        let optimizer = PreOptimizer::new(&config);

        let result = optimizer.eliminate("Help me fix this JWT authentication bug");

        // Should identify security domain as relevant, exclude others
        assert!(!result.excluded_domains.contains(&"security".to_string()));
        assert!(result.excluded_domains.len() > 0);
    }

    #[test]
    fn test_contextualization() {
        let config = MicroConfig::default();
        let optimizer = PreOptimizer::new(&config);

        let result = optimizer.contextualize("Implement JWT token validation", &[]);

        assert!(result.domains.contains(&"security".to_string()));
        assert!(result.relevant_keywords.iter().any(|k| k.contains("jwt") || k.contains("token")));
    }

    #[test]
    fn test_optimize() {
        let config = MicroConfig::default();
        let optimizer = PreOptimizer::new(&config);

        let result = optimizer.optimize(
            "Help me fix the SQL injection vulnerability",
            None,
            &[],
        ).unwrap();

        assert!(!result.full_prompt.is_empty());
        assert!(result.cost_reduction > 0.0);
        assert!(result.stats.elimination_ratio > 0.0);
    }

    #[test]
    fn test_needs_big_compute() {
        let config = MicroConfig::default();
        let optimizer = PreOptimizer::new(&config);

        // Simple query
        assert!(!optimizer.needs_big_compute("What is JWT?"));

        // Complex query
        assert!(optimizer.needs_big_compute("Design and implement a distributed authentication system with OAuth2"));
    }

    #[test]
    fn test_optimized_prompt_structure() {
        let config = MicroConfig::default();
        let optimizer = PreOptimizer::new(&config);

        let result = optimizer.optimize(
            "Create a secure API endpoint",
            Some("Previous context about REST"),
            &[],
        ).unwrap();

        assert!(result.full_prompt.contains("DOMAIN:"));
        assert!(result.original == "Create a secure API endpoint");
    }
}
