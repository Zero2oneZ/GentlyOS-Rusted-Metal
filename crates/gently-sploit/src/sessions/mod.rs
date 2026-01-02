//! Session Management

use crate::Result;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub session_type: SessionType,
    pub target_host: String,
    pub target_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub username: Option<String>,
    pub platform: String,
    pub arch: String,
    pub opened_at: DateTime<Utc>,
    pub last_checkin: DateTime<Utc>,
    pub tunnel: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionType {
    Shell,
    Meterpreter,
    SSH,
    VNC,
    RDP,
}

impl Session {
    pub fn new(id: &str, session_type: SessionType, target: &str, port: u16) -> Self {
        Self {
            id: id.to_string(),
            session_type,
            target_host: target.to_string(),
            target_port: port,
            local_host: "0.0.0.0".to_string(),
            local_port: 4444,
            username: None,
            platform: "unknown".to_string(),
            arch: "unknown".to_string(),
            opened_at: Utc::now(),
            last_checkin: Utc::now(),
            tunnel: None,
        }
    }

    pub fn is_alive(&self) -> bool {
        let timeout = chrono::Duration::seconds(60);
        Utc::now() - self.last_checkin < timeout
    }
}

pub struct SessionManager {
    sessions: HashMap<String, Session>,
    next_id: u32,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create(&mut self, session_type: SessionType, target: &str, port: u16) -> String {
        let id = format!("{}", self.next_id);
        self.next_id += 1;

        let session = Session::new(&id, session_type, target, port);
        self.sessions.insert(id.clone(), session);
        id
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn list(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }

    pub fn kill(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    pub fn kill_all(&mut self) {
        self.sessions.clear();
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        lines.push("Active sessions".to_string());
        lines.push("===============".to_string());
        lines.push(String::new());

        if self.sessions.is_empty() {
            lines.push("  No active sessions.".to_string());
        } else {
            lines.push(format!("  {:4} {:12} {:20} {:8} {:10}",
                "Id", "Type", "Connection", "Platform", "Opened"));
            lines.push(format!("  {:4} {:12} {:20} {:8} {:10}",
                "--", "----", "----------", "--------", "------"));

            for session in self.sessions.values() {
                let type_str = match session.session_type {
                    SessionType::Shell => "shell",
                    SessionType::Meterpreter => "meterpreter",
                    SessionType::SSH => "ssh",
                    SessionType::VNC => "vnc",
                    SessionType::RDP => "rdp",
                };
                let conn = format!("{}:{}", session.target_host, session.target_port);
                let opened = session.opened_at.format("%H:%M:%S").to_string();

                lines.push(format!("  {:4} {:12} {:20} {:8} {:10}",
                    session.id, type_str, conn, session.platform, opened));
            }
        }

        lines.join("\n")
    }
}
