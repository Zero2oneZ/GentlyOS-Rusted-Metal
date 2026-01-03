//! Router Module
//!
//! Intelligent request routing with LOCAL-FIRST priority.
//!
//! Routing Priority:
//! 1. GentlyAssistant (local) - THE STAR
//! 2. Embedder (local) - THE STAR for embeddings
//! 3. Ollama (local/hybrid)
//! 4. External APIs (Claude, OpenAI, Groq)

use crate::{
    GatewayRequest, GatewayError, Result,
    provider::{Provider, ProviderType, ProviderStatus},
    types::{ProviderPreference, TaskType},
};
use std::sync::Arc;
use std::collections::HashMap;

/// Router - Decides which provider handles each request
pub struct Router {
    /// Registered providers
    providers: HashMap<String, Arc<dyn Provider>>,
    /// Default routing strategy
    strategy: RoutingStrategy,
    /// Provider priority order
    priority: Vec<String>,
}

impl Router {
    /// Create new router with local-first strategy
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            strategy: RoutingStrategy::LocalFirst,
            priority: vec![
                "gently-assistant".to_string(),  // THE STAR
                "gently-embedder".to_string(),   // THE STAR
                "ollama".to_string(),            // Local/Hybrid
                "groq".to_string(),              // Fast external
                "claude".to_string(),            // Quality external
                "openai".to_string(),            // Popular external
            ],
        }
    }

    /// Register a provider
    pub fn register(&mut self, provider: Arc<dyn Provider>) {
        self.providers.insert(provider.name().to_string(), provider);
    }

    /// Set routing strategy
    pub fn strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set custom priority order
    pub fn priority(mut self, priority: Vec<String>) -> Self {
        self.priority = priority;
        self
    }

    /// Route a request to the appropriate provider
    pub fn route(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        // Check for explicit preference
        if let Some(pref) = &request.preferred_provider {
            return self.route_by_preference(request, pref);
        }

        // Route by strategy
        match self.strategy {
            RoutingStrategy::LocalFirst => self.route_local_first(request),
            RoutingStrategy::LocalOnly => self.route_local_only(request),
            RoutingStrategy::CostOptimized => self.route_cost_optimized(request),
            RoutingStrategy::QualityOptimized => self.route_quality_optimized(request),
            RoutingStrategy::RoundRobin => self.route_round_robin(request),
            RoutingStrategy::ByTaskType => self.route_by_task_type(request),
        }
    }

    /// Route by explicit preference
    fn route_by_preference(&self, request: &GatewayRequest, pref: &ProviderPreference) -> Result<RouteDecision> {
        match pref {
            ProviderPreference::LocalOnly => self.route_local_only(request),
            ProviderPreference::LocalFirst => self.route_local_first(request),
            ProviderPreference::Specific(name) => self.route_specific(request, name),
            ProviderPreference::Any => self.route_any_available(request),
            ProviderPreference::CostOptimized => self.route_cost_optimized(request),
            ProviderPreference::QualityOptimized => self.route_quality_optimized(request),
        }
    }

    /// LOCAL FIRST - The default and recommended strategy
    fn route_local_first(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        // For embeddings, use Embedder
        if request.task_type == TaskType::Embedding {
            if let Some(provider) = self.providers.get("gently-embedder") {
                return Ok(RouteDecision {
                    provider: "gently-embedder".to_string(),
                    provider_instance: Arc::clone(provider),
                    reason: "Local embedder for embedding tasks".to_string(),
                    fallback: Some("ollama".to_string()),
                });
            }
        }

        // For everything else, try local first
        for name in &self.priority {
            if let Some(provider) = self.providers.get(name) {
                if provider.is_local() || matches!(provider.provider_type(), ProviderType::Hybrid) {
                    // Check capabilities match task
                    let caps = provider.capabilities();
                    if self.can_handle_task(&caps, &request.task_type) {
                        return Ok(RouteDecision {
                            provider: name.clone(),
                            provider_instance: Arc::clone(provider),
                            reason: format!("Local-first: {} selected", name),
                            fallback: self.find_fallback(name),
                        });
                    }
                }
            }
        }

        // Fallback to external
        self.route_any_available(request)
    }

    /// LOCAL ONLY - Never use external APIs
    fn route_local_only(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        for name in &self.priority {
            if let Some(provider) = self.providers.get(name) {
                if provider.is_local() {
                    let caps = provider.capabilities();
                    if self.can_handle_task(&caps, &request.task_type) {
                        return Ok(RouteDecision {
                            provider: name.clone(),
                            provider_instance: Arc::clone(provider),
                            reason: "Local-only mode".to_string(),
                            fallback: None,
                        });
                    }
                }
            }
        }

        Err(GatewayError::ProviderUnavailable(
            "No local provider available for this task".to_string()
        ))
    }

    /// Route to specific provider
    fn route_specific(&self, _request: &GatewayRequest, name: &str) -> Result<RouteDecision> {
        if let Some(provider) = self.providers.get(name) {
            Ok(RouteDecision {
                provider: name.to_string(),
                provider_instance: Arc::clone(provider),
                reason: format!("Explicitly requested: {}", name),
                fallback: self.find_fallback(name),
            })
        } else {
            Err(GatewayError::ProviderUnavailable(
                format!("Provider not found: {}", name)
            ))
        }
    }

    /// Route to any available provider
    fn route_any_available(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        for name in &self.priority {
            if let Some(provider) = self.providers.get(name) {
                let caps = provider.capabilities();
                if self.can_handle_task(&caps, &request.task_type) {
                    return Ok(RouteDecision {
                        provider: name.clone(),
                        provider_instance: Arc::clone(provider),
                        reason: "First available provider".to_string(),
                        fallback: self.find_fallback(name),
                    });
                }
            }
        }

        Err(GatewayError::ProviderUnavailable(
            "No provider available".to_string()
        ))
    }

    /// Cost optimized - prefer free/cheap providers
    fn route_cost_optimized(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        let mut best: Option<(String, Arc<dyn Provider>, f64)> = None;

        for (name, provider) in &self.providers {
            let caps = provider.capabilities();
            if self.can_handle_task(&caps, &request.task_type) {
                let cost = provider.cost_per_1k_tokens();
                if best.is_none() || cost < best.as_ref().unwrap().2 {
                    best = Some((name.clone(), Arc::clone(provider), cost));
                }
            }
        }

        match best {
            Some((name, provider, cost)) => Ok(RouteDecision {
                provider: name.clone(),
                provider_instance: provider,
                reason: format!("Cost optimized: ${:.4}/1K tokens", cost),
                fallback: self.find_fallback(&name),
            }),
            None => Err(GatewayError::ProviderUnavailable(
                "No provider available for cost optimization".to_string()
            )),
        }
    }

    /// Quality optimized - prefer best providers
    fn route_quality_optimized(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        // Quality order: Claude Opus > GPT-4o > Claude Sonnet > Local
        let quality_order = vec!["claude", "openai", "groq", "gently-assistant", "ollama"];

        for name in quality_order {
            if let Some(provider) = self.providers.get(name) {
                let caps = provider.capabilities();
                if self.can_handle_task(&caps, &request.task_type) {
                    return Ok(RouteDecision {
                        provider: name.to_string(),
                        provider_instance: Arc::clone(provider),
                        reason: "Quality optimized".to_string(),
                        fallback: self.find_fallback(name),
                    });
                }
            }
        }

        self.route_any_available(request)
    }

    /// Round robin (simple load balancing)
    fn route_round_robin(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        // For simplicity, just use first available
        // Real implementation would track and rotate
        self.route_any_available(request)
    }

    /// Route by task type
    fn route_by_task_type(&self, request: &GatewayRequest) -> Result<RouteDecision> {
        match request.task_type {
            TaskType::Embedding => {
                // Embedder is THE STAR for embeddings
                self.route_specific(request, "gently-embedder")
                    .or_else(|_| self.route_specific(request, "ollama"))
                    .or_else(|_| self.route_specific(request, "openai"))
            }
            TaskType::CodeGen | TaskType::CodeReview => {
                // Local Llama for code
                self.route_local_first(request)
            }
            TaskType::Creative | TaskType::ToolUse | TaskType::Agent => {
                // Prefer Claude for complex tasks
                self.route_specific(request, "claude")
                    .or_else(|_| self.route_local_first(request))
            }
            TaskType::Security => {
                // ALWAYS LOCAL for security tasks
                self.route_local_only(request)
            }
            _ => self.route_local_first(request),
        }
    }

    /// Check if provider can handle task type
    fn can_handle_task(&self, caps: &crate::provider::ProviderCapabilities, task: &TaskType) -> bool {
        match task {
            TaskType::Embedding => caps.embeddings,
            TaskType::Chat | TaskType::QA | TaskType::Summary | TaskType::Translation => caps.chat,
            TaskType::CodeGen | TaskType::CodeReview | TaskType::Creative => caps.chat,
            TaskType::ToolUse | TaskType::Agent => caps.tools,
            TaskType::Security => caps.chat,
        }
    }

    /// Find fallback provider
    fn find_fallback(&self, current: &str) -> Option<String> {
        let idx = self.priority.iter().position(|p| p == current)?;
        self.priority.get(idx + 1).cloned()
    }

    /// Get all registered providers
    pub fn providers(&self) -> &HashMap<String, Arc<dyn Provider>> {
        &self.providers
    }

    /// Check health of all providers
    pub async fn health_check_all(&self) -> HashMap<String, ProviderStatus> {
        let mut results = HashMap::new();
        for (name, provider) in &self.providers {
            results.insert(name.clone(), provider.health_check().await);
        }
        results
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Try local first, fallback to external
    LocalFirst,
    /// Only use local providers
    LocalOnly,
    /// Prefer cheapest providers
    CostOptimized,
    /// Prefer highest quality providers
    QualityOptimized,
    /// Round-robin load balancing
    RoundRobin,
    /// Route based on task type
    ByTaskType,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        Self::LocalFirst
    }
}

/// Route decision
pub struct RouteDecision {
    /// Selected provider name
    pub provider: String,
    /// Provider instance
    pub provider_instance: Arc<dyn Provider>,
    /// Reason for selection
    pub reason: String,
    /// Fallback provider (if primary fails)
    pub fallback: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::GentlyAssistantProvider;

    #[test]
    fn test_router_creation() {
        let router = Router::new();
        assert!(router.providers.is_empty());
        assert_eq!(router.strategy, RoutingStrategy::LocalFirst);
    }

    #[test]
    fn test_register_provider() {
        let mut router = Router::new();
        let provider = Arc::new(GentlyAssistantProvider::new());
        router.register(provider);
        assert!(router.providers.contains_key("gently-assistant"));
    }
}
