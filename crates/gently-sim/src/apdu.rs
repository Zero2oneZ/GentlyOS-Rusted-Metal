//! APDU traffic analysis and logging
//!
//! For use with SIMtrace2 or PC/SC reader to capture all SIM communication.

use crate::{OtaEvent, OtaEventType, RiskLevel};
use sha2::Digest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// APDU traffic analyzer
pub struct ApduAnalyzer {
    /// Recent APDU history for pattern detection
    history: VecDeque<ApduRecord>,
    /// Maximum history size
    max_history: usize,
    /// Detected suspicious patterns
    alerts: Vec<ApduAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApduRecord {
    pub timestamp: DateTime<Utc>,
    pub direction: ApduDirection,
    pub command: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub sw: Option<u16>,
    pub interpretation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ApduDirection {
    /// Command from terminal to SIM
    ToSim,
    /// Response from SIM to terminal
    FromSim,
    /// Proactive command from SIM (STK)
    Proactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApduAlert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: ApduAlertType,
    pub description: String,
    pub risk_level: RiskLevel,
    pub related_apdus: Vec<ApduRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApduAlertType {
    /// STK proactive command detected
    ProactiveCommand,
    /// Binary SMS processing
    BinarySmsProcessing,
    /// OTA command sequence
    OtaSequence,
    /// Unusual file access
    UnusualFileAccess,
    /// Key material access
    KeyAccess,
    /// Simjacker-like pattern
    SimjackerPattern,
    /// Unknown applet selection
    UnknownApplet,
}

impl ApduAnalyzer {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(max_history),
            max_history,
            alerts: Vec::new(),
        }
    }

    /// Record an APDU exchange
    pub fn record(&mut self, record: ApduRecord) {
        // Analyze before storing
        self.analyze(&record);

        // Store in history
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(record);
    }

    /// Analyze an APDU for suspicious patterns
    fn analyze(&mut self, record: &ApduRecord) {
        let cmd = &record.command;

        if cmd.len() < 4 {
            return;
        }

        let ins = cmd[1];

        match ins {
            // FETCH - STK proactive command
            0x12 => {
                self.alerts.push(ApduAlert {
                    timestamp: record.timestamp,
                    alert_type: ApduAlertType::ProactiveCommand,
                    description: "STK FETCH command - SIM initiating action".to_string(),
                    risk_level: RiskLevel::Medium,
                    related_apdus: vec![record.clone()],
                });
            }

            // TERMINAL RESPONSE - completing STK command
            0x14 => {
                self.alerts.push(ApduAlert {
                    timestamp: record.timestamp,
                    alert_type: ApduAlertType::ProactiveCommand,
                    description: "STK TERMINAL RESPONSE - completing proactive command".to_string(),
                    risk_level: RiskLevel::Medium,
                    related_apdus: vec![record.clone()],
                });
            }

            // ENVELOPE - SMS/USSD delivery to SIM apps
            0xC2 => {
                // Check for binary SMS (tag D1 = SMS-PP download)
                if cmd.len() > 5 && cmd[5] == 0xD1 {
                    self.alerts.push(ApduAlert {
                        timestamp: record.timestamp,
                        alert_type: ApduAlertType::BinarySmsProcessing,
                        description: "Binary SMS delivered to SIM application".to_string(),
                        risk_level: RiskLevel::High,
                        related_apdus: vec![record.clone()],
                    });
                }
            }

            // SELECT - file or application selection
            0xA4 => {
                if cmd.len() >= 7 {
                    let fid = format!("{:02X}{:02X}", cmd[5], cmd[6]);

                    // Check for S@T Browser selection
                    if fid == "6F3A" {
                        self.alerts.push(ApduAlert {
                            timestamp: record.timestamp,
                            alert_type: ApduAlertType::SimjackerPattern,
                            description: "S@T Browser file selected - Simjacker attack vector".to_string(),
                            risk_level: RiskLevel::Critical,
                            related_apdus: vec![record.clone()],
                        });
                    }

                    // Check for key file access
                    if fid == "6F20" || fid == "6F78" {
                        self.alerts.push(ApduAlert {
                            timestamp: record.timestamp,
                            alert_type: ApduAlertType::KeyAccess,
                            description: format!("Cryptographic key file {} accessed", fid),
                            risk_level: RiskLevel::High,
                            related_apdus: vec![record.clone()],
                        });
                    }
                }
            }

            _ => {}
        }
    }

    /// Interpret an APDU command
    pub fn interpret_command(cmd: &[u8]) -> String {
        if cmd.len() < 2 {
            return "Invalid APDU".to_string();
        }

        let ins = cmd[1];

        match ins {
            0xA4 => {
                if cmd.len() >= 7 {
                    format!("SELECT {:02X}{:02X}", cmd[5], cmd[6])
                } else {
                    "SELECT".to_string()
                }
            }
            0xB0 => "READ BINARY".to_string(),
            0xB2 => "READ RECORD".to_string(),
            0xD6 => "UPDATE BINARY".to_string(),
            0xDC => "UPDATE RECORD".to_string(),
            0x20 => "VERIFY PIN".to_string(),
            0x24 => "CHANGE PIN".to_string(),
            0x12 => "FETCH (STK)".to_string(),
            0x14 => "TERMINAL RESPONSE (STK)".to_string(),
            0xC2 => "ENVELOPE".to_string(),
            0xC0 => "GET RESPONSE".to_string(),
            0xF2 => "STATUS".to_string(),
            0x88 => "RUN GSM ALGORITHM".to_string(),
            0x89 => "AUTHENTICATE".to_string(),
            _ => format!("INS={:02X}", ins),
        }
    }

    /// Get recent alerts
    pub fn get_alerts(&self) -> &[ApduAlert] {
        &self.alerts
    }

    /// Get alerts by risk level
    pub fn get_alerts_by_risk(&self, min_risk: RiskLevel) -> Vec<&ApduAlert> {
        self.alerts.iter()
            .filter(|a| a.risk_level as u8 >= min_risk as u8)
            .collect()
    }

    /// Clear alerts
    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    /// Export history for analysis
    pub fn export_history(&self) -> Vec<ApduRecord> {
        self.history.iter().cloned().collect()
    }
}

/// Detect OTA sequences in APDU traffic
pub fn detect_ota_sequence(history: &[ApduRecord]) -> Vec<OtaEvent> {
    let mut events = Vec::new();

    // Look for patterns indicating OTA activity:
    // 1. Binary SMS (ENVELOPE with D1 tag)
    // 2. Followed by FETCH commands
    // 3. Potentially followed by file updates or applet installs

    let mut in_ota_sequence = false;
    let mut _sequence_start: Option<DateTime<Utc>> = None;

    for record in history {
        let cmd = &record.command;
        if cmd.len() < 2 {
            continue;
        }

        let ins = cmd[1];

        // ENVELOPE with SMS-PP download
        if ins == 0xC2 && cmd.len() > 5 && cmd[5] == 0xD1 {
            in_ota_sequence = true;
            _sequence_start = Some(record.timestamp);
        }

        // If in OTA sequence, look for specific actions
        if in_ota_sequence {
            // UPDATE commands during OTA = file modification
            if ins == 0xD6 || ins == 0xDC {
                events.push(OtaEvent {
                    timestamp: record.timestamp,
                    event_type: OtaEventType::FileModify,
                    source: None,
                    pdu_hash: hex::encode(sha2::Sha256::digest(cmd)),
                    authorized: false, // Assume unauthorized until verified
                });
            }

            // INSTALL command (GlobalPlatform)
            if ins == 0xE6 || ins == 0xE8 {
                events.push(OtaEvent {
                    timestamp: record.timestamp,
                    event_type: OtaEventType::AppletInstall,
                    source: None,
                    pdu_hash: hex::encode(sha2::Sha256::digest(cmd)),
                    authorized: false,
                });
                in_ota_sequence = false;
            }
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpret_select() {
        let cmd = vec![0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        assert_eq!(ApduAnalyzer::interpret_command(&cmd), "SELECT 3F00");
    }

    #[test]
    fn test_interpret_read_binary() {
        let cmd = vec![0xA0, 0xB0, 0x00, 0x00, 0xFF];
        assert_eq!(ApduAnalyzer::interpret_command(&cmd), "READ BINARY");
    }

    #[test]
    fn test_analyzer_detects_proactive() {
        let mut analyzer = ApduAnalyzer::new(100);

        let record = ApduRecord {
            timestamp: Utc::now(),
            direction: ApduDirection::ToSim,
            command: vec![0xA0, 0x12, 0x00, 0x00, 0x20],
            response: None,
            sw: None,
            interpretation: None,
        };

        analyzer.record(record);

        let alerts = analyzer.get_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, ApduAlertType::ProactiveCommand);
    }

    #[test]
    fn test_analyzer_detects_simjacker() {
        let mut analyzer = ApduAnalyzer::new(100);

        // SELECT 6F3A (S@T Browser)
        let record = ApduRecord {
            timestamp: Utc::now(),
            direction: ApduDirection::ToSim,
            command: vec![0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x3A],
            response: None,
            sw: None,
            interpretation: None,
        };

        analyzer.record(record);

        let alerts = analyzer.get_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, ApduAlertType::SimjackerPattern);
        assert_eq!(alerts[0].risk_level, RiskLevel::Critical);
    }
}
