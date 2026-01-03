//! Rate Limiter
//!
//! 5-layer rate limiting system:
//! 1. Global - System-wide limits
//! 2. Per-Provider - Limits per AI provider
//! 3. Per-Token - Limits per auth token
//! 4. Per-Session - Limits per session
//! 5. Cost-Based - Limits based on token cost

use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};

/// Rate limiter with 5 layers
pub struct RateLimiter {
    /// Layer configurations
    layers: Vec<RateLimitLayer>,
    /// Bucket storage
    buckets: HashMap<String, TokenBucket>,
    /// Statistics
    stats: RateLimitStats,
}

impl RateLimiter {
    /// Create new rate limiter with default configuration
    pub fn new() -> Self {
        Self {
            layers: vec![
                RateLimitLayer::Global {
                    requests_per_minute: 1000,
                    tokens_per_minute: 1_000_000,
                },
                RateLimitLayer::PerProvider {
                    requests_per_minute: 100,
                    tokens_per_minute: 100_000,
                },
                RateLimitLayer::PerAuthToken {
                    requests_per_minute: 60,
                    tokens_per_minute: 50_000,
                },
                RateLimitLayer::PerSession {
                    requests_per_minute: 30,
                    tokens_per_minute: 25_000,
                },
                RateLimitLayer::CostBased {
                    max_cost_per_minute: 100.0, // cents
                    max_cost_per_hour: 1000.0,
                },
            ],
            buckets: HashMap::new(),
            stats: RateLimitStats::default(),
        }
    }

    /// Create with custom layers
    pub fn with_layers(layers: Vec<RateLimitLayer>) -> Self {
        Self {
            layers,
            buckets: HashMap::new(),
            stats: RateLimitStats::default(),
        }
    }

    /// Check if request is allowed
    pub fn check(&mut self, context: &RateLimitContext) -> RateLimitResult {
        for layer in &self.layers {
            let bucket_key = self.get_bucket_key(layer, context);
            let bucket = self.buckets.entry(bucket_key.clone())
                .or_insert_with(|| TokenBucket::new(layer.capacity(), layer.refill_rate()));

            if !bucket.try_consume(1) {
                self.stats.rejected += 1;
                return RateLimitResult::Rejected {
                    layer: layer.name().to_string(),
                    retry_after: bucket.time_until_tokens(1),
                };
            }
        }

        self.stats.allowed += 1;
        RateLimitResult::Allowed
    }

    /// Record token usage (for cost-based limiting)
    pub fn record_usage(&mut self, context: &RateLimitContext, tokens: usize, cost: f64) {
        let cost_key = format!("cost:{}:{}",
            context.auth_token.as_deref().unwrap_or("anonymous"),
            context.session_id.as_deref().unwrap_or("none")
        );

        let bucket = self.buckets.entry(cost_key)
            .or_insert_with(|| TokenBucket::new(10000, 10000.0 / 60.0));

        // Cost is tracked in hundredths of a cent
        let cost_units = (cost * 100.0) as u64;
        bucket.force_consume(cost_units);

        self.stats.total_tokens += tokens;
        self.stats.total_cost += cost;
    }

    /// Get statistics
    pub fn stats(&self) -> &RateLimitStats {
        &self.stats
    }

    /// Get bucket key for layer
    fn get_bucket_key(&self, layer: &RateLimitLayer, context: &RateLimitContext) -> String {
        match layer {
            RateLimitLayer::Global { .. } => "global".to_string(),
            RateLimitLayer::PerProvider { .. } => format!("provider:{}", context.provider),
            RateLimitLayer::PerAuthToken { .. } => format!("token:{}",
                context.auth_token.as_deref().unwrap_or("anonymous")),
            RateLimitLayer::PerSession { .. } => format!("session:{}",
                context.session_id.as_deref().unwrap_or("none")),
            RateLimitLayer::CostBased { .. } => format!("cost:{}",
                context.auth_token.as_deref().unwrap_or("anonymous")),
        }
    }

    /// Clean up old buckets
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < max_age
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limit layer types
#[derive(Debug, Clone)]
pub enum RateLimitLayer {
    /// Global system-wide limits
    Global {
        requests_per_minute: u64,
        tokens_per_minute: u64,
    },
    /// Per AI provider limits
    PerProvider {
        requests_per_minute: u64,
        tokens_per_minute: u64,
    },
    /// Per authentication token limits
    PerAuthToken {
        requests_per_minute: u64,
        tokens_per_minute: u64,
    },
    /// Per session limits
    PerSession {
        requests_per_minute: u64,
        tokens_per_minute: u64,
    },
    /// Cost-based limits
    CostBased {
        max_cost_per_minute: f64,  // in cents
        max_cost_per_hour: f64,
    },
}

impl RateLimitLayer {
    /// Get layer name
    pub fn name(&self) -> &str {
        match self {
            Self::Global { .. } => "global",
            Self::PerProvider { .. } => "per_provider",
            Self::PerAuthToken { .. } => "per_token",
            Self::PerSession { .. } => "per_session",
            Self::CostBased { .. } => "cost_based",
        }
    }

    /// Get bucket capacity
    fn capacity(&self) -> u64 {
        match self {
            Self::Global { requests_per_minute, .. } => *requests_per_minute,
            Self::PerProvider { requests_per_minute, .. } => *requests_per_minute,
            Self::PerAuthToken { requests_per_minute, .. } => *requests_per_minute,
            Self::PerSession { requests_per_minute, .. } => *requests_per_minute,
            Self::CostBased { max_cost_per_minute, .. } => (*max_cost_per_minute * 100.0) as u64,
        }
    }

    /// Get refill rate (tokens per second)
    fn refill_rate(&self) -> f64 {
        match self {
            Self::Global { requests_per_minute, .. } => *requests_per_minute as f64 / 60.0,
            Self::PerProvider { requests_per_minute, .. } => *requests_per_minute as f64 / 60.0,
            Self::PerAuthToken { requests_per_minute, .. } => *requests_per_minute as f64 / 60.0,
            Self::PerSession { requests_per_minute, .. } => *requests_per_minute as f64 / 60.0,
            Self::CostBased { max_cost_per_minute, .. } => *max_cost_per_minute * 100.0 / 60.0,
        }
    }
}

/// Context for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// Provider being used
    pub provider: String,
    /// Auth token (if any)
    pub auth_token: Option<String>,
    /// Session ID (if any)
    pub session_id: Option<String>,
    /// Estimated tokens
    pub estimated_tokens: usize,
    /// Estimated cost (cents)
    pub estimated_cost: f64,
}

impl RateLimitContext {
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            auth_token: None,
            session_id: None,
            estimated_tokens: 0,
            estimated_cost: 0.0,
        }
    }

    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn tokens(mut self, tokens: usize) -> Self {
        self.estimated_tokens = tokens;
        self
    }

    pub fn cost(mut self, cost: f64) -> Self {
        self.estimated_cost = cost;
        self
    }
}

/// Rate limit result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request is rejected
    Rejected {
        /// Which layer rejected
        layer: String,
        /// When to retry
        retry_after: Duration,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Current tokens available
    tokens: f64,
    /// Maximum capacity
    capacity: u64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last update time
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            capacity,
            refill_rate,
            last_update: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_update = now;
    }

    fn try_consume(&mut self, count: u64) -> bool {
        self.refill();
        if self.tokens >= count as f64 {
            self.tokens -= count as f64;
            true
        } else {
            false
        }
    }

    fn force_consume(&mut self, count: u64) {
        self.refill();
        self.tokens -= count as f64;
    }

    fn time_until_tokens(&self, count: u64) -> Duration {
        if self.tokens >= count as f64 {
            Duration::ZERO
        } else {
            let needed = count as f64 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

/// Rate limit statistics
#[derive(Debug, Clone, Default)]
pub struct RateLimitStats {
    /// Requests allowed
    pub allowed: u64,
    /// Requests rejected
    pub rejected: u64,
    /// Total tokens processed
    pub total_tokens: usize,
    /// Total cost incurred
    pub total_cost: f64,
}

impl RateLimitStats {
    /// Get rejection rate
    pub fn rejection_rate(&self) -> f64 {
        let total = self.allowed + self.rejected;
        if total == 0 {
            0.0
        } else {
            self.rejected as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        let context = RateLimitContext::new("claude")
            .auth_token("test-token")
            .session("session-1");

        // First request should be allowed
        assert!(limiter.check(&context).is_allowed());
    }

    #[test]
    fn test_burst_limiting() {
        let mut limiter = RateLimiter::with_layers(vec![
            RateLimitLayer::PerSession {
                requests_per_minute: 5,
                tokens_per_minute: 1000,
            },
        ]);

        let context = RateLimitContext::new("claude")
            .session("burst-test");

        // First 5 should pass
        for _ in 0..5 {
            assert!(limiter.check(&context).is_allowed());
        }

        // 6th should fail
        assert!(!limiter.check(&context).is_allowed());
    }

    #[test]
    fn test_stats() {
        let mut limiter = RateLimiter::new();
        let context = RateLimitContext::new("claude");

        limiter.check(&context);
        limiter.record_usage(&context, 100, 0.5);

        assert_eq!(limiter.stats().allowed, 1);
        assert_eq!(limiter.stats().total_tokens, 100);
        assert_eq!(limiter.stats().total_cost, 0.5);
    }
}
