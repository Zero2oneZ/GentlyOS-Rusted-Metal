//! Trust System
//!
//! "IT'S DEFINITELY ATTACKING YOUR COMPUTER"
//!
//! Assume-hostile trust model with decay.
//! Everyone starts as Hostile and must earn trust.

use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

/// Trust system manager
pub struct TrustSystem {
    /// Trust states by entity ID
    states: HashMap<String, TrustState>,
    /// Trust decay rate per hour
    decay_rate: f64,
    /// Configuration
    config: TrustConfig,
}

impl TrustSystem {
    /// Create new trust system
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            decay_rate: 0.05, // 5% per hour
            config: TrustConfig::default(),
        }
    }

    /// Get or create trust state for entity
    pub fn get_state(&mut self, entity_id: &str) -> &TrustState {
        if !self.states.contains_key(entity_id) {
            self.states.insert(entity_id.to_string(), TrustState::new());
        }
        self.apply_decay(entity_id);
        self.states.get(entity_id).unwrap()
    }

    /// Get mutable trust state
    pub fn get_state_mut(&mut self, entity_id: &str) -> &mut TrustState {
        if !self.states.contains_key(entity_id) {
            self.states.insert(entity_id.to_string(), TrustState::new());
        }
        self.apply_decay(entity_id);
        self.states.get_mut(entity_id).unwrap()
    }

    /// Record positive action (builds trust)
    pub fn record_positive(&mut self, entity_id: &str, action: &str, weight: f64) {
        let state = self.get_state_mut(entity_id);
        state.add_trust(weight, action);
    }

    /// Record negative action (destroys trust)
    pub fn record_negative(&mut self, entity_id: &str, action: &str, weight: f64) {
        let state = self.get_state_mut(entity_id);
        state.remove_trust(weight, action);
    }

    /// Record violation (immediate hostile)
    pub fn record_violation(&mut self, entity_id: &str, violation: &str) {
        let state = self.get_state_mut(entity_id);
        state.record_violation(violation);
    }

    /// Check if entity is allowed to perform action
    pub fn is_allowed(&mut self, entity_id: &str, action: &TrustAction) -> bool {
        let required_level = self.config.required_level_for(action);
        let state = self.get_state(entity_id);
        state.level >= required_level
    }

    /// Apply time-based decay
    fn apply_decay(&mut self, entity_id: &str) {
        if let Some(state) = self.states.get_mut(entity_id) {
            let now = Utc::now();
            let hours = now.signed_duration_since(state.last_update)
                .num_minutes() as f64 / 60.0;

            if hours > 0.0 {
                let decay = self.decay_rate * hours;
                state.score = (state.score * (1.0 - decay)).max(0.0);
                state.update_level();
                state.last_update = now;
            }
        }
    }

    /// Get all entities at or below a trust level
    pub fn get_untrusted(&self, max_level: TrustLevel) -> Vec<&str> {
        self.states.iter()
            .filter(|(_, state)| state.level <= max_level)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Cleanup old states
    pub fn cleanup(&mut self, max_age: Duration) {
        let cutoff = Utc::now() - max_age;
        self.states.retain(|_, state| state.last_update > cutoff);
    }
}

impl Default for TrustSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust state for a single entity
#[derive(Debug, Clone)]
pub struct TrustState {
    /// Current trust level
    pub level: TrustLevel,
    /// Trust score (0-100)
    pub score: f64,
    /// Last update time
    pub last_update: DateTime<Utc>,
    /// Created time
    pub created_at: DateTime<Utc>,
    /// Violations recorded
    pub violations: Vec<Violation>,
    /// Positive actions recorded
    pub positive_actions: Vec<TrustAction>,
    /// Is permanently hostile (unrecoverable)
    pub permanently_hostile: bool,
}

impl TrustState {
    /// Create new trust state (starts as Hostile)
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            level: TrustLevel::Hostile,  // EVERYONE starts hostile
            score: 0.0,
            last_update: now,
            created_at: now,
            violations: Vec::new(),
            positive_actions: Vec::new(),
            permanently_hostile: false,
        }
    }

    /// Add trust
    pub fn add_trust(&mut self, amount: f64, action: &str) {
        if self.permanently_hostile {
            return;  // No redemption
        }

        self.score = (self.score + amount).min(100.0);
        self.positive_actions.push(TrustAction::Custom(action.to_string()));
        self.update_level();
        self.last_update = Utc::now();
    }

    /// Remove trust
    pub fn remove_trust(&mut self, amount: f64, action: &str) {
        self.score = (self.score - amount).max(0.0);
        self.update_level();
        self.last_update = Utc::now();
    }

    /// Record violation (severe trust impact)
    pub fn record_violation(&mut self, description: &str) {
        self.violations.push(Violation {
            description: description.to_string(),
            timestamp: Utc::now(),
        });

        // Violations heavily impact trust
        self.score = (self.score - 50.0).max(0.0);

        // 3+ violations = permanently hostile
        if self.violations.len() >= 3 {
            self.permanently_hostile = true;
            self.level = TrustLevel::Hostile;
            self.score = 0.0;
        } else {
            self.update_level();
        }

        self.last_update = Utc::now();
    }

    /// Update level based on score
    fn update_level(&mut self) {
        if self.permanently_hostile {
            self.level = TrustLevel::Hostile;
            return;
        }

        self.level = match self.score {
            s if s >= 80.0 => TrustLevel::Provisional,  // Max trust level
            s if s >= 60.0 => TrustLevel::Monitored,
            s if s >= 40.0 => TrustLevel::Suspicious,
            s if s >= 20.0 => TrustLevel::Untrusted,
            _ => TrustLevel::Hostile,
        };
    }

    /// Get age in hours
    pub fn age_hours(&self) -> f64 {
        Utc::now().signed_duration_since(self.created_at).num_minutes() as f64 / 60.0
    }
}

impl Default for TrustState {
    fn default() -> Self {
        Self::new()
    }
}

/// Trust levels (from lowest to highest)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Hostile - actively attacking, full restrictions
    Hostile,
    /// Untrusted - new entity, heavy restrictions
    Untrusted,
    /// Suspicious - some concerning behavior
    Suspicious,
    /// Monitored - watching closely
    Monitored,
    /// Provisional - earned some trust, still verified
    Provisional,
    // Note: No "Trusted" level - everyone is always provisional at best
}

impl TrustLevel {
    /// Get display name
    pub fn name(&self) -> &str {
        match self {
            Self::Hostile => "HOSTILE",
            Self::Untrusted => "UNTRUSTED",
            Self::Suspicious => "SUSPICIOUS",
            Self::Monitored => "MONITORED",
            Self::Provisional => "PROVISIONAL",
        }
    }

    /// Get required score for this level
    pub fn required_score(&self) -> f64 {
        match self {
            Self::Hostile => 0.0,
            Self::Untrusted => 20.0,
            Self::Suspicious => 40.0,
            Self::Monitored => 60.0,
            Self::Provisional => 80.0,
        }
    }
}

/// Trust actions
#[derive(Debug, Clone)]
pub enum TrustAction {
    /// Basic API access
    ApiAccess,
    /// External provider access
    ExternalProvider,
    /// Tool execution
    ToolExecution,
    /// File access
    FileAccess,
    /// Network access
    NetworkAccess,
    /// Admin actions
    AdminAction,
    /// Custom action
    Custom(String),
}

/// Violation record
#[derive(Debug, Clone)]
pub struct Violation {
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

/// Trust configuration
#[derive(Debug, Clone)]
pub struct TrustConfig {
    /// Required levels for actions
    action_levels: HashMap<String, TrustLevel>,
}

impl TrustConfig {
    /// Get required level for action
    pub fn required_level_for(&self, action: &TrustAction) -> TrustLevel {
        let key = match action {
            TrustAction::ApiAccess => "api_access",
            TrustAction::ExternalProvider => "external_provider",
            TrustAction::ToolExecution => "tool_execution",
            TrustAction::FileAccess => "file_access",
            TrustAction::NetworkAccess => "network_access",
            TrustAction::AdminAction => "admin_action",
            TrustAction::Custom(s) => s.as_str(),
        };

        self.action_levels.get(key).copied().unwrap_or(TrustLevel::Monitored)
    }
}

impl Default for TrustConfig {
    fn default() -> Self {
        let mut action_levels = HashMap::new();

        // Set required levels
        action_levels.insert("api_access".to_string(), TrustLevel::Untrusted);
        action_levels.insert("external_provider".to_string(), TrustLevel::Monitored);
        action_levels.insert("tool_execution".to_string(), TrustLevel::Monitored);
        action_levels.insert("file_access".to_string(), TrustLevel::Monitored);
        action_levels.insert("network_access".to_string(), TrustLevel::Provisional);
        action_levels.insert("admin_action".to_string(), TrustLevel::Provisional);

        Self { action_levels }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_entity_is_hostile() {
        let mut system = TrustSystem::new();
        let state = system.get_state("new_user");
        assert_eq!(state.level, TrustLevel::Hostile);
    }

    #[test]
    fn test_trust_building() {
        let mut system = TrustSystem::new();

        // Build trust through positive actions
        for i in 0..10 {
            system.record_positive("user1", &format!("action_{}", i), 10.0);
        }

        let state = system.get_state("user1");
        assert!(state.level > TrustLevel::Hostile);
    }

    #[test]
    fn test_violation_impact() {
        let mut system = TrustSystem::new();

        // Build some trust
        system.record_positive("user1", "good_action", 50.0);

        // Record violation
        system.record_violation("user1", "injection_attempt");

        let state = system.get_state("user1");
        assert!(state.score < 50.0);
    }

    #[test]
    fn test_permanent_hostile() {
        let mut system = TrustSystem::new();

        // 3 violations = permanent hostile
        system.record_violation("attacker", "violation_1");
        system.record_violation("attacker", "violation_2");
        system.record_violation("attacker", "violation_3");

        let state = system.get_state("attacker");
        assert!(state.permanently_hostile);
        assert_eq!(state.level, TrustLevel::Hostile);

        // Cannot recover
        system.record_positive("attacker", "nice_action", 100.0);
        let state = system.get_state("attacker");
        assert_eq!(state.level, TrustLevel::Hostile);
    }
}
