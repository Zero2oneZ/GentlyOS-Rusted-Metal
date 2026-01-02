//! Software Firewall
//!
//! Default: DENY ALL. Explicit allow for trusted connections.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Software firewall for GentlyOS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Firewall {
    rules: Vec<FirewallRule>,
    blocked_ips: HashSet<String>,
    allowed_ips: HashSet<String>,
    default_action: RuleAction,
    enabled: bool,
}

impl Firewall {
    /// Create a new firewall (default: deny all)
    pub fn new() -> Self {
        let mut fw = Self {
            rules: Vec::new(),
            blocked_ips: HashSet::new(),
            allowed_ips: HashSet::new(),
            default_action: RuleAction::Deny,
            enabled: true,
        };

        // Always allow localhost
        fw.allow("127.0.0.1");
        fw.allow("::1");

        fw
    }

    /// Check if a connection should be allowed
    pub fn check(&self, ip: &str, port: u16, direction: Direction) -> RuleAction {
        if !self.enabled {
            return RuleAction::Allow;
        }

        // Check explicit blocks first
        if self.blocked_ips.contains(ip) {
            return RuleAction::Deny;
        }

        // Check explicit allows
        if self.allowed_ips.contains(ip) {
            return RuleAction::Allow;
        }

        // Check rules
        for rule in &self.rules {
            if rule.matches(ip, port, direction) {
                return rule.action;
            }
        }

        // Default action
        self.default_action
    }

    /// Block an IP
    pub fn block(&mut self, ip: &str) {
        self.blocked_ips.insert(ip.to_string());
        self.allowed_ips.remove(ip);
    }

    /// Allow an IP
    pub fn allow(&mut self, ip: &str) {
        self.allowed_ips.insert(ip.to_string());
        self.blocked_ips.remove(ip);
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
    }

    /// Enable/disable firewall
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get all rules
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    /// Get blocked IPs
    pub fn blocked(&self) -> &HashSet<String> {
        &self.blocked_ips
    }

    /// Get allowed IPs
    pub fn allowed(&self) -> &HashSet<String> {
        &self.allowed_ips
    }

    /// Is enabled?
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

/// A firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub ip_pattern: Option<String>,
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
    pub direction: Option<Direction>,
    pub action: RuleAction,
    pub enabled: bool,
}

impl FirewallRule {
    /// Create a new rule
    pub fn new(name: impl Into<String>, action: RuleAction) -> Self {
        Self {
            name: name.into(),
            ip_pattern: None,
            port: None,
            port_range: None,
            direction: None,
            action,
            enabled: true,
        }
    }

    /// Match against IP pattern
    pub fn with_ip(mut self, pattern: impl Into<String>) -> Self {
        self.ip_pattern = Some(pattern.into());
        self
    }

    /// Match against port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Match against port range
    pub fn with_port_range(mut self, start: u16, end: u16) -> Self {
        self.port_range = Some((start, end));
        self
    }

    /// Match direction
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Check if rule matches
    pub fn matches(&self, ip: &str, port: u16, direction: Direction) -> bool {
        if !self.enabled {
            return false;
        }

        // Check IP pattern
        if let Some(pattern) = &self.ip_pattern {
            if !self.ip_matches(ip, pattern) {
                return false;
            }
        }

        // Check port
        if let Some(p) = self.port {
            if port != p {
                return false;
            }
        }

        // Check port range
        if let Some((start, end)) = self.port_range {
            if port < start || port > end {
                return false;
            }
        }

        // Check direction
        if let Some(d) = self.direction {
            if direction != d {
                return false;
            }
        }

        true
    }

    fn ip_matches(&self, ip: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('.').collect();
            let ip_parts: Vec<&str> = ip.split('.').collect();

            if parts.len() != ip_parts.len() {
                return false;
            }

            for (p, i) in parts.iter().zip(ip_parts.iter()) {
                if *p != "*" && p != i {
                    return false;
                }
            }

            true
        } else {
            ip == pattern
        }
    }
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Log,  // Allow but log
}

/// Connection direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_default_deny() {
        let fw = Firewall::new();

        // Localhost allowed
        assert_eq!(fw.check("127.0.0.1", 80, Direction::Inbound), RuleAction::Allow);

        // External denied
        assert_eq!(fw.check("8.8.8.8", 80, Direction::Outbound), RuleAction::Deny);
    }

    #[test]
    fn test_firewall_allow() {
        let mut fw = Firewall::new();
        fw.allow("8.8.8.8");

        assert_eq!(fw.check("8.8.8.8", 53, Direction::Outbound), RuleAction::Allow);
    }

    #[test]
    fn test_rule_matching() {
        let rule = FirewallRule::new("block_google", RuleAction::Deny)
            .with_ip("142.250.*.*")
            .with_direction(Direction::Outbound);

        assert!(rule.matches("142.250.1.1", 443, Direction::Outbound));
        assert!(!rule.matches("142.250.1.1", 443, Direction::Inbound));
        assert!(!rule.matches("8.8.8.8", 443, Direction::Outbound));
    }
}
