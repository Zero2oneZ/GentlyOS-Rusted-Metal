//! Security Suite for Architect Coder
//!
//! Session logging, file locking, and SVG export.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Security monitor for Architect Coder sessions
pub struct ArchitectSecurity {
    pub session_id: Uuid,
    logs: Vec<SecurityEvent>,
    locks: HashMap<PathBuf, LockState>,
    monitors: Vec<MonitorTarget>,
}

impl ArchitectSecurity {
    /// Create a new security session
    pub fn new() -> Self {
        let session_id = Uuid::new_v4();

        let mut security = Self {
            session_id,
            logs: Vec::new(),
            locks: HashMap::new(),
            monitors: Vec::new(),
        };

        security.log(EventKind::SessionStart, "architect", EventStatus::Active);
        security
    }

    /// Log an event
    pub fn log(&mut self, event: EventKind, target: &str, status: EventStatus) {
        self.logs.push(SecurityEvent {
            timestamp: timestamp_now(),
            event,
            target: target.to_string(),
            status,
            xor_signature: None,
        });
    }

    /// Log with XOR signature
    pub fn log_signed(&mut self, event: EventKind, target: &str, status: EventStatus, signature: [u8; 32]) {
        self.logs.push(SecurityEvent {
            timestamp: timestamp_now(),
            event,
            target: target.to_string(),
            status,
            xor_signature: Some(signature),
        });
    }

    /// Lock a file (simulated XOR lock)
    pub fn lock_file(&mut self, path: &Path) -> crate::Result<()> {
        if self.locks.contains_key(path) {
            return Err(crate::Error::AlreadyLocked(path.display().to_string()));
        }

        // Simulate generating a lock
        let lock_hash = simulate_xor_hash(path);

        self.locks.insert(
            path.to_path_buf(),
            LockState::Locked {
                lock_hash,
                locked_at: timestamp_now(),
                by: self.session_id,
            },
        );

        self.log(EventKind::FileLocked, &path.display().to_string(), EventStatus::Success);
        Ok(())
    }

    /// Check if a file is locked
    pub fn is_locked(&self, path: &Path) -> bool {
        matches!(self.locks.get(path), Some(LockState::Locked { .. }))
    }

    /// Unlock a file (requires simulated Dance)
    pub fn unlock_file(&mut self, path: &Path, dance_session: Uuid) -> crate::Result<()> {
        // In real implementation, this would verify Dance Protocol completion
        self.locks.insert(
            path.to_path_buf(),
            LockState::Unlocked {
                unlocked_at: timestamp_now(),
                by_dance: dance_session,
            },
        );

        self.log(EventKind::FileUnlocked, &path.display().to_string(), EventStatus::Success);
        Ok(())
    }

    /// Add a monitor target
    pub fn monitor(&mut self, target: MonitorTarget) {
        self.monitors.push(target.clone());
        self.log(
            EventKind::LaunchCommand { cmd: target.name.clone() },
            &target.name,
            EventStatus::Pending,
        );
    }

    /// Get recent logs
    pub fn recent_logs(&self, count: usize) -> Vec<&SecurityEvent> {
        self.logs.iter().rev().take(count).collect()
    }

    /// Get all locks
    pub fn locks(&self) -> &HashMap<PathBuf, LockState> {
        &self.locks
    }

    /// Get statistics
    pub fn stats(&self) -> SecurityStats {
        SecurityStats {
            total_events: self.logs.len(),
            locked_files: self.locks.values().filter(|l| matches!(l, LockState::Locked { .. })).count(),
            unlocked_files: self.locks.values().filter(|l| matches!(l, LockState::Unlocked { .. })).count(),
            active_monitors: self.monitors.len(),
        }
    }

    /// End session
    pub fn end_session(&mut self) {
        self.log(EventKind::SessionEnd, "architect", EventStatus::Success);
    }

    /// Export session as SVG timeline
    pub fn export_svg(&self, output: &Path) -> crate::Result<String> {
        let mut svg = String::new();
        svg.push_str(&format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 {}">"#,
            100 + self.logs.len() * 40
        ));

        svg.push_str(r#"
<style>
    .bg { fill: #0d0d1a; }
    .title { fill: #00ffff; font-family: monospace; font-size: 24px; }
    .event { fill: #1a1a2e; stroke: #00ffff; stroke-width: 1; }
    .event-success { fill: #162447; stroke: #00ff88; }
    .event-locked { fill: #2d1b4e; stroke: #ff00ff; }
    .text { fill: #ffffff; font-family: monospace; font-size: 12px; }
    .timestamp { fill: #888888; font-family: monospace; font-size: 10px; }
    .line { stroke: #00ffff; stroke-width: 2; stroke-dasharray: 5,5; }
</style>
"#);

        // Background
        svg.push_str(&format!(
            r#"<rect class="bg" x="0" y="0" width="1200" height="{}"/>"#,
            100 + self.logs.len() * 40
        ));

        // Title
        svg.push_str(&format!(
            r#"<text class="title" x="50" y="40">Session: {}</text>"#,
            self.session_id
        ));

        // Timeline
        svg.push_str(r#"<line class="line" x1="100" y1="70" x2="100" y2="9999"/>"#);

        // Events
        for (i, event) in self.logs.iter().enumerate() {
            let y = 90 + i * 40;
            let class = match event.status {
                EventStatus::Success => "event-success",
                EventStatus::Locked => "event-locked",
                _ => "event",
            };

            svg.push_str(&format!(
                r#"<rect class="{}" x="120" y="{}" width="800" height="30" rx="5"/>"#,
                class, y
            ));

            svg.push_str(&format!(
                r#"<text class="text" x="130" y="{}">{}: {}</text>"#,
                y + 20,
                event.event.label(),
                event.target
            ));

            svg.push_str(&format!(
                r#"<text class="timestamp" x="950" y="{}">{}</text>"#,
                y + 20,
                format_timestamp(event.timestamp)
            ));

            // Connector to timeline
            svg.push_str(&format!(
                r##"<circle cx="100" cy="{}" r="5" fill="#00ffff"/>"##,
                y + 15
            ));
        }

        svg.push_str("</svg>");

        // Write to file
        std::fs::write(output, &svg)?;

        self.logs.last().map(|_| {
            // Can't log here due to borrow, but in real code we'd log export
        });

        Ok(svg)
    }

    /// Render logs as ASCII table
    pub fn render_logs_ascii(&self, count: usize) -> String {
        let mut lines = Vec::new();
        lines.push("┌────────────┬──────────────────────┬────────────────────┬──────────────┐".to_string());
        lines.push("│ TIME       │ EVENT                │ TARGET             │ STATUS       │".to_string());
        lines.push("├────────────┼──────────────────────┼────────────────────┼──────────────┤".to_string());

        for event in self.logs.iter().rev().take(count) {
            let time = format_timestamp(event.timestamp);
            let status_str = match event.status {
                EventStatus::Success => "██ SUCCESS",
                EventStatus::Pending => "░░ PENDING",
                EventStatus::Failed { .. } => "XX FAILED",
                EventStatus::Locked => "🔒 LOCKED",
                EventStatus::Active => "▓▓ ACTIVE",
            };

            lines.push(format!(
                "│ {:10} │ {:20} │ {:18} │ {:12} │",
                time,
                event.event.label(),
                truncate(&event.target, 18),
                status_str
            ));
        }

        lines.push("└────────────┴──────────────────────┴────────────────────┴──────────────┘".to_string());
        lines.join("\n")
    }
}

impl Default for ArchitectSecurity {
    fn default() -> Self {
        Self::new()
    }
}

/// A security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event: EventKind,
    pub target: String,
    pub status: EventStatus,
    pub xor_signature: Option<[u8; 32]>,
}

/// Types of security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    SessionStart,
    SessionEnd,
    IdeaSpoken,
    IdeaConfirmed,
    IdeaCrystallized,
    FileLocked,
    FileUnlocked,
    DanceInitiated,
    DanceCompleted,
    LaunchCommand { cmd: String },
    ExportSvg { path: PathBuf },
}

impl EventKind {
    pub fn label(&self) -> &str {
        match self {
            EventKind::SessionStart => "SESSION_START",
            EventKind::SessionEnd => "SESSION_END",
            EventKind::IdeaSpoken => "IDEA_SPOKEN",
            EventKind::IdeaConfirmed => "IDEA_CONFIRM",
            EventKind::IdeaCrystallized => "CRYSTALLIZE",
            EventKind::FileLocked => "FILE_LOCK",
            EventKind::FileUnlocked => "FILE_UNLOCK",
            EventKind::DanceInitiated => "DANCE_INIT",
            EventKind::DanceCompleted => "DANCE_DONE",
            EventKind::LaunchCommand { .. } => "LAUNCH",
            EventKind::ExportSvg { .. } => "EXPORT_SVG",
        }
    }
}

/// Status of an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventStatus {
    Success,
    Pending,
    Failed { reason: String },
    Locked,
    Active,
}

/// Lock state for files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockState {
    Locked {
        lock_hash: [u8; 32],
        locked_at: u64,
        by: Uuid,
    },
    Unlocked {
        unlocked_at: u64,
        by_dance: Uuid,
    },
}

/// A target being monitored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorTarget {
    pub name: String,
    pub kind: MonitorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorKind {
    File { path: PathBuf },
    Process { pid: u32 },
    Command { cmd: String },
}

#[derive(Debug)]
pub struct SecurityStats {
    pub total_events: usize,
    pub locked_files: usize,
    pub unlocked_files: usize,
    pub active_monitors: usize,
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_timestamp(ts: u64) -> String {
    // Simple HH:MM:SS format
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

fn simulate_xor_hash(path: &Path) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    let hash = hasher.finish();

    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&hash.to_le_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_session() {
        let mut security = ArchitectSecurity::new();

        security.log(EventKind::IdeaSpoken, "test idea", EventStatus::Success);
        assert_eq!(security.logs.len(), 2); // SessionStart + IdeaSpoken

        security.end_session();
        assert_eq!(security.logs.len(), 3);
    }

    #[test]
    fn test_file_locking() {
        let mut security = ArchitectSecurity::new();
        let path = Path::new("test.rs");

        security.lock_file(path).unwrap();
        assert!(security.is_locked(path));

        // Can't lock again
        assert!(security.lock_file(path).is_err());

        // Unlock
        security.unlock_file(path, Uuid::new_v4()).unwrap();
        assert!(!security.is_locked(path));
    }
}
