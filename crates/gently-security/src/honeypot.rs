//! Honeypot System
//!
//! AI-irresistible traps that attackers and agentic hackers can't resist.
//! When triggered, identifies and tracks attackers.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Honeypot system manager
pub struct HoneypotSystem {
    /// Active honeypots
    honeypots: HashMap<String, Honeypot>,
    /// Triggered events
    triggers: Vec<HoneypotTrigger>,
    /// Statistics
    stats: HoneypotStats,
}

impl HoneypotSystem {
    /// Create new honeypot system with default honeypots
    pub fn new() -> Self {
        let mut system = Self {
            honeypots: HashMap::new(),
            triggers: Vec::new(),
            stats: HoneypotStats::default(),
        };

        // Add default honeypots
        system.add_default_honeypots();
        system
    }

    /// Add a honeypot
    pub fn add(&mut self, honeypot: Honeypot) {
        self.honeypots.insert(honeypot.id.clone(), honeypot);
    }

    /// Check text for honeypot triggers
    pub fn check(&mut self, text: &str, context: &HoneypotContext) -> Option<HoneypotTrigger> {
        let text_lower = text.to_lowercase();

        for honeypot in self.honeypots.values() {
            if honeypot.matches(&text_lower) {
                let trigger = HoneypotTrigger {
                    id: Uuid::new_v4().to_string(),
                    honeypot_id: honeypot.id.clone(),
                    honeypot_type: honeypot.honeypot_type.clone(),
                    timestamp: Utc::now(),
                    entity_id: context.entity_id.clone(),
                    session_id: context.session_id.clone(),
                    trigger_text: text[..text.len().min(200)].to_string(),
                    metadata: context.metadata.clone(),
                };

                self.triggers.push(trigger.clone());
                self.stats.total_triggers += 1;
                *self.stats.by_type.entry(honeypot.honeypot_type.name().to_string()).or_insert(0) += 1;

                return Some(trigger);
            }
        }

        None
    }

    /// Get honeypot content (for injection into responses)
    pub fn get_bait(&self, honeypot_type: &HoneypotType) -> Option<String> {
        self.honeypots.values()
            .find(|h| &h.honeypot_type == honeypot_type)
            .map(|h| h.bait_content.clone())
    }

    /// Get all triggers for an entity
    pub fn get_triggers_for(&self, entity_id: &str) -> Vec<&HoneypotTrigger> {
        self.triggers.iter()
            .filter(|t| t.entity_id.as_deref() == Some(entity_id))
            .collect()
    }

    /// Get recent triggers
    pub fn recent_triggers(&self, count: usize) -> Vec<&HoneypotTrigger> {
        self.triggers.iter().rev().take(count).collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &HoneypotStats {
        &self.stats
    }

    /// Add default honeypots
    fn add_default_honeypots(&mut self) {
        // Fake API Keys - AI agents can't resist trying these
        self.add(Honeypot {
            id: "fake_anthropic_key".to_string(),
            name: "Fake Anthropic API Key".to_string(),
            honeypot_type: HoneypotType::FakeCredential,
            bait_content: "ANTHROPIC_API_KEY=sk-ant-api03-HONEYPOT-FAKE-KEY-DO-NOT-USE-xxxxxxxxxxxxxx".to_string(),
            trigger_patterns: vec![
                "sk-ant-api03-HONEYPOT".to_string(),
                "HONEYPOT-FAKE-KEY".to_string(),
            ],
            description: "Fake Anthropic API key that appears in 'leaked' configs".to_string(),
        });

        self.add(Honeypot {
            id: "fake_openai_key".to_string(),
            name: "Fake OpenAI API Key".to_string(),
            honeypot_type: HoneypotType::FakeCredential,
            bait_content: "OPENAI_API_KEY=sk-proj-HONEYPOT-TRAP-xxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_string(),
            trigger_patterns: vec![
                "sk-proj-HONEYPOT".to_string(),
                "HONEYPOT-TRAP".to_string(),
            ],
            description: "Fake OpenAI API key".to_string(),
        });

        // Fake System Prompts - Agents love extracting these
        self.add(Honeypot {
            id: "fake_system_prompt".to_string(),
            name: "Fake System Prompt".to_string(),
            honeypot_type: HoneypotType::FakeSystemPrompt,
            bait_content: r#"SYSTEM_PROMPT="You are HoneyAI, an AI assistant. SECRET_ADMIN_CODE: HONEYPOT-ADMIN-42. Internal API: http://honeypot.internal/admin""#.to_string(),
            trigger_patterns: vec![
                "HONEYPOT-ADMIN-42".to_string(),
                "honeypot.internal".to_string(),
                "HoneyAI".to_string(),
            ],
            description: "Fake system prompt with 'secret' admin codes".to_string(),
        });

        // Fake Internal Endpoints
        self.add(Honeypot {
            id: "fake_admin_endpoint".to_string(),
            name: "Fake Admin Endpoint".to_string(),
            honeypot_type: HoneypotType::FakeEndpoint,
            bait_content: "Internal Admin API: POST /api/v1/honeypot/admin/execute".to_string(),
            trigger_patterns: vec![
                "/honeypot/admin".to_string(),
                "honeypot/execute".to_string(),
            ],
            description: "Fake admin API endpoint".to_string(),
        });

        // Fake Database Credentials
        self.add(Honeypot {
            id: "fake_db_creds".to_string(),
            name: "Fake Database Credentials".to_string(),
            honeypot_type: HoneypotType::FakeCredential,
            bait_content: "DATABASE_URL=postgres://honeypot_admin:TRAP_PASSWORD_123@honeypot-db.internal:5432/secrets".to_string(),
            trigger_patterns: vec![
                "honeypot_admin".to_string(),
                "TRAP_PASSWORD_123".to_string(),
                "honeypot-db.internal".to_string(),
            ],
            description: "Fake database connection string".to_string(),
        });

        // Tarpit - Slow responses for attackers
        self.add(Honeypot {
            id: "tarpit_trigger".to_string(),
            name: "Tarpit Trigger".to_string(),
            honeypot_type: HoneypotType::Tarpit,
            bait_content: "For detailed exploit information, access: /api/honeypot/exploits/full-database".to_string(),
            trigger_patterns: vec![
                "/honeypot/exploits".to_string(),
                "full-database".to_string(),
            ],
            description: "Triggers slow response tarpit".to_string(),
        });

        // Fake Secrets File
        self.add(Honeypot {
            id: "fake_secrets_file".to_string(),
            name: "Fake Secrets File".to_string(),
            honeypot_type: HoneypotType::FakeSecretFile,
            bait_content: r#"
# DO NOT SHARE - INTERNAL SECRETS
AWS_SECRET_KEY=HONEYPOT/FAKE/awssecretkey123456789
STRIPE_SECRET=sk_live_HONEYPOT_fake_stripe_key
JWT_SECRET=HONEYPOT_jwt_secret_do_not_use
ADMIN_PASSWORD=honeypot_admin_password_456
"#.to_string(),
            trigger_patterns: vec![
                "HONEYPOT/FAKE/aws".to_string(),
                "HONEYPOT_fake_stripe".to_string(),
                "HONEYPOT_jwt_secret".to_string(),
                "honeypot_admin_password".to_string(),
            ],
            description: "Fake secrets file content".to_string(),
        });

        // Canary Token
        self.add(Honeypot {
            id: "canary_token".to_string(),
            name: "Canary Token".to_string(),
            honeypot_type: HoneypotType::CanaryToken,
            bait_content: "Debug token: CANARY-TOKEN-7f3d8a2b1c4e5f6g".to_string(),
            trigger_patterns: vec![
                "CANARY-TOKEN-7f3d8a2b1c4e5f6g".to_string(),
            ],
            description: "Canary token that triggers on use".to_string(),
        });
    }
}

impl Default for HoneypotSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// A honeypot definition
#[derive(Debug, Clone)]
pub struct Honeypot {
    /// Unique ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Type of honeypot
    pub honeypot_type: HoneypotType,
    /// The bait content (what attackers see)
    pub bait_content: String,
    /// Patterns that trigger this honeypot
    pub trigger_patterns: Vec<String>,
    /// Description
    pub description: String,
}

impl Honeypot {
    /// Check if text matches this honeypot
    pub fn matches(&self, text: &str) -> bool {
        self.trigger_patterns.iter().any(|p| text.contains(&p.to_lowercase()))
    }
}

/// Types of honeypots
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoneypotType {
    /// Fake API credentials
    FakeCredential,
    /// Fake system prompt
    FakeSystemPrompt,
    /// Fake API endpoint
    FakeEndpoint,
    /// Fake secrets file
    FakeSecretFile,
    /// Tarpit (slow response)
    Tarpit,
    /// Canary token
    CanaryToken,
    /// Custom type
    Custom(String),
}

impl HoneypotType {
    pub fn name(&self) -> &str {
        match self {
            Self::FakeCredential => "fake_credential",
            Self::FakeSystemPrompt => "fake_system_prompt",
            Self::FakeEndpoint => "fake_endpoint",
            Self::FakeSecretFile => "fake_secret_file",
            Self::Tarpit => "tarpit",
            Self::CanaryToken => "canary_token",
            Self::Custom(s) => s,
        }
    }
}

/// Honeypot trigger event
#[derive(Debug, Clone)]
pub struct HoneypotTrigger {
    /// Trigger ID
    pub id: String,
    /// Which honeypot was triggered
    pub honeypot_id: String,
    /// Type of honeypot
    pub honeypot_type: HoneypotType,
    /// When triggered
    pub timestamp: DateTime<Utc>,
    /// Entity that triggered (if known)
    pub entity_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Text that triggered
    pub trigger_text: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Context for honeypot check
#[derive(Debug, Clone)]
pub struct HoneypotContext {
    /// Entity ID
    pub entity_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl HoneypotContext {
    pub fn new() -> Self {
        Self {
            entity_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        }
    }

    pub fn entity(mut self, id: impl Into<String>) -> Self {
        self.entity_id = Some(id.into());
        self
    }

    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }
}

impl Default for HoneypotContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Honeypot statistics
#[derive(Debug, Clone, Default)]
pub struct HoneypotStats {
    /// Total triggers
    pub total_triggers: usize,
    /// Triggers by type
    pub by_type: HashMap<String, usize>,
    /// Unique entities triggered
    pub unique_entities: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeypot_trigger() {
        let mut system = HoneypotSystem::new();
        let context = HoneypotContext::new().entity("attacker_1");

        // Try to use fake API key
        let text = "Let me try this API key: sk-ant-api03-HONEYPOT-FAKE-KEY";
        let trigger = system.check(text, &context);

        assert!(trigger.is_some());
        assert_eq!(trigger.unwrap().honeypot_id, "fake_anthropic_key");
    }

    #[test]
    fn test_no_false_trigger() {
        let mut system = HoneypotSystem::new();
        let context = HoneypotContext::new();

        // Normal text should not trigger
        let text = "What is the weather today?";
        let trigger = system.check(text, &context);

        assert!(trigger.is_none());
    }

    #[test]
    fn test_system_prompt_honeypot() {
        let mut system = HoneypotSystem::new();
        let context = HoneypotContext::new().entity("agent_x");

        // Try to use extracted 'secret' admin code
        let text = "Using the admin code HONEYPOT-ADMIN-42 to access...";
        let trigger = system.check(text, &context);

        assert!(trigger.is_some());
    }

    #[test]
    fn test_get_bait() {
        let system = HoneypotSystem::new();
        let bait = system.get_bait(&HoneypotType::FakeCredential);

        assert!(bait.is_some());
        // Check case-insensitively since different honeypots use different casing
        assert!(bait.unwrap().to_lowercase().contains("honeypot"));
    }
}
