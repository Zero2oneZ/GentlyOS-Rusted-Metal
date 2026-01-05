//! Context-aware search router
//!
//! Routes queries through domains and filters by Living Feed context.

use crate::{domain::DomainRouter, wormhole::Wormhole, Thought, ThoughtIndex};
use gently_feed::LivingFeed;
use serde::{Deserialize, Serialize};

/// A search result with ranking info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// The thought
    pub thought: Thought,

    /// Relevance score (0.0-1.0)
    pub score: f32,

    /// Why it matched
    pub match_reason: MatchReason,

    /// Related wormholes (cross-context jumps)
    pub wormholes: Vec<Wormhole>,
}

/// Why a result matched
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchReason {
    /// Direct content match
    ContentMatch { query_term: String },
    /// Keyword match
    KeywordMatch { keywords: Vec<String> },
    /// Domain match
    DomainMatch { domain: u8 },
    /// Tag match
    TagMatch { tag: String },
    /// Wormhole jump from another result
    WormholeJump { from_id: String },
    /// Feed context boost
    FeedBoost { item_name: String },
}

/// Context-aware search router
pub struct ContextRouter {
    /// Domain router for 72-domain semantic routing
    pub domain_router: DomainRouter,
    max_results: usize,
    enable_wormholes: bool,
    enable_feed_boost: bool,
}

impl Default for ContextRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextRouter {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            domain_router: DomainRouter::new(),
            max_results: 20,
            enable_wormholes: true,
            enable_feed_boost: true,
        }
    }

    /// Set max results
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Enable/disable wormhole expansion
    pub fn with_wormholes(mut self, enabled: bool) -> Self {
        self.enable_wormholes = enabled;
        self
    }

    /// Enable/disable feed context boosting
    pub fn with_feed_boost(mut self, enabled: bool) -> Self {
        self.enable_feed_boost = enabled;
        self
    }

    /// Search with context
    pub fn search(
        &self,
        query: &str,
        index: &ThoughtIndex,
        feed: Option<&LivingFeed>,
    ) -> Vec<SearchResult> {
        let mut results = Vec::new();

        // 1. Route query to domains
        let domain_routes = self.domain_router.route(query);
        let primary_domain = domain_routes.first().map(|(d, _)| *d);

        // 2. Search thoughts
        let query_lower = query.to_lowercase();
        let query_terms: Vec<&str> = query_lower.split_whitespace().collect();

        for thought in index.thoughts() {
            let mut score = 0.0_f32;
            let mut match_reason = None;

            // Content match (highest priority)
            if thought.content.to_lowercase().contains(&query_lower) {
                score += 0.8;
                match_reason = Some(MatchReason::ContentMatch {
                    query_term: query.to_string(),
                });
            }

            // Keyword match
            let keyword_matches: Vec<_> = thought
                .shape
                .keywords
                .iter()
                .filter(|kw| query_terms.iter().any(|qt| kw.contains(qt) || qt.contains(kw.as_str())))
                .cloned()
                .collect();

            if !keyword_matches.is_empty() {
                score += 0.3 * keyword_matches.len() as f32;
                if match_reason.is_none() {
                    match_reason = Some(MatchReason::KeywordMatch {
                        keywords: keyword_matches,
                    });
                }
            }

            // Domain match
            if let Some(domain) = primary_domain {
                if thought.shape.domain == domain {
                    score += 0.2;
                    if match_reason.is_none() {
                        match_reason = Some(MatchReason::DomainMatch { domain });
                    }
                }
            }

            // Tag match
            for tag in &thought.tags {
                if query_terms.iter().any(|qt| tag.to_lowercase().contains(qt)) {
                    score += 0.2;
                    if match_reason.is_none() {
                        match_reason = Some(MatchReason::TagMatch { tag: tag.clone() });
                    }
                    break;
                }
            }

            // Feed context boost
            if self.enable_feed_boost {
                if let Some(feed) = feed {
                    // Check if thought content mentions any hot feed items
                    for hot_item in feed.hot_items() {
                        if thought
                            .content
                            .to_lowercase()
                            .contains(&hot_item.name.to_lowercase())
                        {
                            score += 0.3 * hot_item.charge;
                            if match_reason.is_none() {
                                match_reason = Some(MatchReason::FeedBoost {
                                    item_name: hot_item.name.clone(),
                                });
                            }
                            break;
                        }
                    }
                }
            }

            // Apply recency/popularity from thought
            score *= 1.0 + thought.relevance_score() * 0.5;

            if score > 0.0 {
                results.push(SearchResult {
                    thought: thought.clone(),
                    score,
                    match_reason: match_reason.unwrap_or(MatchReason::ContentMatch {
                        query_term: query.to_string(),
                    }),
                    wormholes: Vec::new(),
                });
            }
        }

        // Sort by score
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // 3. Expand via wormholes (add related results)
        if self.enable_wormholes && !results.is_empty() {
            let top_ids: Vec<_> = results.iter().take(5).map(|r| r.thought.id).collect();

            for result in &mut results {
                // Find wormholes from this thought
                let wormholes: Vec<_> = index
                    .wormholes()
                    .iter()
                    .filter(|w| w.connects(result.thought.id))
                    .cloned()
                    .collect();

                result.wormholes = wormholes;
            }

            // Add wormhole-discovered thoughts (that aren't already in results)
            let existing_ids: std::collections::HashSet<_> =
                results.iter().map(|r| r.thought.id).collect();

            for top_id in top_ids {
                for wormhole in index.wormholes() {
                    if let Some(other_id) = wormhole.other_end(top_id) {
                        if !existing_ids.contains(&other_id) {
                            if let Some(thought) = index.get_thought(other_id) {
                                results.push(SearchResult {
                                    thought: thought.clone(),
                                    score: wormhole.similarity * 0.5,
                                    match_reason: MatchReason::WormholeJump {
                                        from_id: top_id.to_string(),
                                    },
                                    wormholes: vec![wormhole.clone()],
                                });
                            }
                        }
                    }
                }
            }

            // Re-sort after adding wormhole results
            results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        }

        // Truncate to max
        results.truncate(self.max_results);

        results
    }

    /// Quick search (no wormholes, no feed boost)
    pub fn quick_search(&self, query: &str, index: &ThoughtIndex) -> Vec<SearchResult> {
        let router = ContextRouter::new()
            .with_wormholes(false)
            .with_feed_boost(false)
            .with_max_results(10);

        router.search(query, index, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThoughtIndex;

    #[test]
    fn test_basic_search() {
        let mut index = ThoughtIndex::new();
        index.add_thought(Thought::new("GentlyOS is a cryptographic security layer"));
        index.add_thought(Thought::new("The Dance Protocol uses XOR operations"));
        index.add_thought(Thought::new("Something completely different"));

        let router = ContextRouter::new();
        let results = router.search("cryptographic", &index, None);

        assert!(!results.is_empty());
        assert!(results[0].thought.content.contains("cryptographic"));
    }

    #[test]
    fn test_domain_routing() {
        let mut index = ThoughtIndex::new();
        index.add_thought(Thought::new("How do I implement security for my application?"));
        index.add_thought(Thought::new("Recipe for chocolate cake"));

        let router = ContextRouter::new();
        // Search for a single term that matches content
        let results = router.search("security", &index, None);

        assert!(!results.is_empty());
        assert!(results[0].thought.content.contains("security"));
    }
}
