//! Network Monitor
//!
//! Track and log all network events.

use crate::firewall::{Direction, RuleAction};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Network event monitor
pub struct NetworkMonitor {
    events: VecDeque<NetworkEvent>,
    max_events: usize,
    stats: MonitorStats,
}

impl NetworkMonitor {
    /// Create a new monitor
    pub fn new(max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_events,
            stats: MonitorStats::default(),
        }
    }

    /// Log an event
    pub fn log(&mut self, event: NetworkEvent) {
        // Update stats
        match event.action {
            RuleAction::Allow => self.stats.allowed += 1,
            RuleAction::Deny => self.stats.blocked += 1,
            RuleAction::Log => self.stats.logged += 1,
        }

        match event.direction {
            Direction::Inbound => self.stats.inbound += 1,
            Direction::Outbound => self.stats.outbound += 1,
        }

        // Add event
        self.events.push_front(event);

        // Trim old events
        while self.events.len() > self.max_events {
            self.events.pop_back();
        }
    }

    /// Get recent events
    pub fn recent(&self, count: usize) -> Vec<&NetworkEvent> {
        self.events.iter().take(count).collect()
    }

    /// Get all events
    pub fn events(&self) -> &VecDeque<NetworkEvent> {
        &self.events
    }

    /// Get stats
    pub fn stats(&self) -> &MonitorStats {
        &self.stats
    }

    /// Clear all events
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Render as ASCII table
    pub fn render_ascii(&self, count: usize) -> String {
        let mut lines = Vec::new();

        lines.push("┌────────────┬──────────┬─────────────────────────┬──────────────┐".to_string());
        lines.push("│ TIME       │ ACTION   │ TARGET                  │ DIRECTION    │".to_string());
        lines.push("├────────────┼──────────┼─────────────────────────┼──────────────┤".to_string());

        for event in self.events.iter().take(count) {
            let time = format_time(event.timestamp);
            let action = match event.action {
                RuleAction::Allow => "ALLOWED",
                RuleAction::Deny => "BLOCKED",
                RuleAction::Log => "LOGGED ",
            };
            let indicator = match event.action {
                RuleAction::Allow => "████",
                RuleAction::Deny => "░░░░",
                RuleAction::Log => "▓▓▓▓",
            };
            let target = format!("{}:{}", event.ip, event.port);
            let direction = match event.direction {
                Direction::Inbound => "← INBOUND ",
                Direction::Outbound => "→ OUTBOUND",
            };

            lines.push(format!(
                "│ {} │ {} {} │ {:23} │ {} │",
                time,
                indicator,
                action,
                truncate(&target, 23),
                direction
            ));
        }

        lines.push("└────────────┴──────────┴─────────────────────────┴──────────────┘".to_string());

        lines.join("\n")
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// A network event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: u64,
    pub ip: String,
    pub port: u16,
    pub direction: Direction,
    pub action: RuleAction,
    pub rule_name: Option<String>,
    pub process: Option<String>,
}

impl NetworkEvent {
    /// Create a new event
    pub fn new(ip: String, port: u16, direction: Direction, action: RuleAction) -> Self {
        Self {
            timestamp: timestamp_now(),
            ip,
            port,
            direction,
            action,
            rule_name: None,
            process: None,
        }
    }

    /// With rule name
    pub fn with_rule(mut self, name: impl Into<String>) -> Self {
        self.rule_name = Some(name.into());
        self
    }

    /// With process name
    pub fn with_process(mut self, name: impl Into<String>) -> Self {
        self.process = Some(name.into());
        self
    }
}

/// Monitor statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MonitorStats {
    pub allowed: u64,
    pub blocked: u64,
    pub logged: u64,
    pub inbound: u64,
    pub outbound: u64,
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_time(ts: u64) -> String {
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{:width$}", s, width = max)
    } else {
        format!("{}...", &s[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor() {
        let mut monitor = NetworkMonitor::new(100);

        monitor.log(NetworkEvent::new(
            "8.8.8.8".into(),
            53,
            Direction::Outbound,
            RuleAction::Deny,
        ));

        assert_eq!(monitor.stats().blocked, 1);
        assert_eq!(monitor.events().len(), 1);
    }
}
