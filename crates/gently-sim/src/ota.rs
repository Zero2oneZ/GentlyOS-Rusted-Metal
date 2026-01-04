//! OTA (Over-The-Air) Detection
//!
//! Detect and analyze OTA activity including binary SMS, applet pushes, and remote updates.

use crate::{OtaEvent, OtaEventType, RiskLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// OTA activity monitor
pub struct OtaMonitor {
    events: Vec<OtaEvent>,
    /// Known authorized OTA sources (carrier SMSCs)
    authorized_sources: Vec<String>,
}

impl OtaMonitor {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            authorized_sources: Vec::new(),
        }
    }

    /// Add authorized OTA source
    pub fn add_authorized_source(&mut self, source: String) {
        self.authorized_sources.push(source);
    }

    /// Check if source is authorized
    pub fn is_authorized(&self, source: &Option<String>) -> bool {
        match source {
            Some(s) => self.authorized_sources.iter().any(|auth| auth == s),
            None => false,
        }
    }

    /// Record an OTA event
    pub fn record_event(&mut self, event: OtaEvent) {
        self.events.push(event);
    }

    /// Parse SMS PDU for OTA indicators
    pub fn analyze_sms_pdu(pdu: &[u8]) -> Option<OtaEventType> {
        if pdu.len() < 10 {
            return None;
        }

        // Check for Type 0 SMS (silent/ping)
        // TP-PID = 0x40 indicates Type 0
        // This is a simplified check - real parsing needs full PDU decode
        let tp_pid_candidates = &pdu[..pdu.len().min(20)];

        for (i, &byte) in tp_pid_candidates.iter().enumerate() {
            // TP-PID for Type 0 SMS
            if byte == 0x40 && i > 0 {
                return Some(OtaEventType::BinarySms);
            }

            // TP-PID for SIM Data Download
            if byte == 0x7F {
                return Some(OtaEventType::StkPush);
            }
        }

        // Check for STK-related DCS (Data Coding Scheme)
        // Class 2 SMS (DCS bits) goes to SIM
        for &byte in tp_pid_candidates {
            // DCS for Class 2 (SIM-specific)
            if (byte & 0xF0) == 0xF0 && (byte & 0x03) == 0x02 {
                return Some(OtaEventType::StkPush);
            }
        }

        None
    }

    /// Parse OTA-SMS for command type
    pub fn parse_ota_command(data: &[u8]) -> OtaEventType {
        if data.len() < 5 {
            return OtaEventType::Unknown;
        }

        // OTA-SMS structure (simplified):
        // CPL (2 bytes) + CHL (1 byte) + SPI (2 bytes) + TAR (3 bytes) + ...

        // Check for known TAR (Toolkit Application Reference)
        if data.len() >= 8 {
            let tar = &data[5..8];

            // TAR for RAM (Remote Applet Management)
            if tar == [0xB0, 0x00, 0x10] {
                return OtaEventType::AppletInstall;
            }

            // TAR for RFM (Remote File Management)
            if tar == [0xB0, 0x00, 0x00] {
                return OtaEventType::FileModify;
            }
        }

        // Check for S@T command push
        // Usually starts with specific BER-TLV structure
        if data.len() > 3 && data[0] == 0xD0 {
            return OtaEventType::SatBrowser;
        }

        OtaEventType::Unknown
    }

    /// Create OTA event from raw PDU
    pub fn create_event(&mut self, pdu: &[u8], source: Option<String>) -> OtaEvent {
        let event_type = Self::analyze_sms_pdu(pdu)
            .unwrap_or_else(|| Self::parse_ota_command(pdu));

        let authorized = self.is_authorized(&source);

        OtaEvent {
            timestamp: Utc::now(),
            event_type,
            source,
            pdu_hash: hex::encode(Sha256::digest(pdu)),
            authorized,
        }
    }

    /// Get all events
    pub fn get_events(&self) -> &[OtaEvent] {
        &self.events
    }

    /// Get unauthorized events
    pub fn get_unauthorized(&self) -> Vec<&OtaEvent> {
        self.events.iter().filter(|e| !e.authorized).collect()
    }

    /// Get events by type
    pub fn get_by_type(&self, event_type: OtaEventType) -> Vec<&OtaEvent> {
        self.events.iter().filter(|e| e.event_type == event_type).collect()
    }

    /// Check for Simjacker attack pattern
    pub fn check_simjacker_pattern(&self) -> Vec<&OtaEvent> {
        self.events.iter()
            .filter(|e| e.event_type == OtaEventType::SatBrowser)
            .collect()
    }

    /// Generate OTA report
    pub fn generate_report(&self) -> OtaReport {
        OtaReport {
            total_events: self.events.len(),
            unauthorized: self.get_unauthorized().len(),
            binary_sms: self.get_by_type(OtaEventType::BinarySms).len(),
            stk_pushes: self.get_by_type(OtaEventType::StkPush).len(),
            applet_installs: self.get_by_type(OtaEventType::AppletInstall).len(),
            file_modifications: self.get_by_type(OtaEventType::FileModify).len(),
            simjacker_attempts: self.check_simjacker_pattern().len(),
            events: self.events.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaReport {
    pub total_events: usize,
    pub unauthorized: usize,
    pub binary_sms: usize,
    pub stk_pushes: usize,
    pub applet_installs: usize,
    pub file_modifications: usize,
    pub simjacker_attempts: usize,
    pub events: Vec<OtaEvent>,
}

impl OtaReport {
    pub fn print(&self) {
        println!("\n  OTA ACTIVITY REPORT");
        println!("  ===================\n");
        println!("  Total events:      {}", self.total_events);
        println!("  Unauthorized:      {}", self.unauthorized);
        println!("  Binary SMS:        {}", self.binary_sms);
        println!("  STK pushes:        {}", self.stk_pushes);
        println!("  Applet installs:   {}", self.applet_installs);
        println!("  File modifications:{}", self.file_modifications);

        if self.simjacker_attempts > 0 {
            println!("\n  ⚠️  SIMJACKER ATTEMPTS DETECTED: {}", self.simjacker_attempts);
        }

        if self.unauthorized > 0 {
            println!("\n  UNAUTHORIZED EVENTS:");
            for event in &self.events {
                if !event.authorized {
                    println!("    {:?} at {} (source: {:?})",
                        event.event_type,
                        event.timestamp,
                        event.source
                    );
                }
            }
        }
    }

    pub fn risk_level(&self) -> RiskLevel {
        if self.simjacker_attempts > 0 {
            return RiskLevel::Critical;
        }
        if self.applet_installs > 0 && self.unauthorized > 0 {
            return RiskLevel::Critical;
        }
        if self.unauthorized > 0 {
            return RiskLevel::High;
        }
        if self.binary_sms > 0 || self.stk_pushes > 0 {
            return RiskLevel::Medium;
        }
        RiskLevel::Low
    }
}

/// Known malicious OTA patterns
pub struct OtaPatterns;

impl OtaPatterns {
    /// Check for known attack signatures
    pub fn check_signature(data: &[u8]) -> Option<&'static str> {
        // Simjacker signature: S@T Browser push with PROVIDE LOCAL INFO
        if data.len() > 10 && data[0] == 0xD0 {
            // Check for PROVIDE LOCAL INFO command (0x26)
            if data.iter().any(|&b| b == 0x26) {
                return Some("Simjacker: Location tracking via S@T Browser");
            }

            // Check for SEND SHORT MESSAGE (0x13)
            if data.iter().any(|&b| b == 0x13) {
                return Some("Simjacker: Exfiltration via silent SMS");
            }
        }

        // WIBAttack signature
        if data.len() > 5 && data[0] == 0x01 {
            return Some("WIBattack: Possible WIB-based attack");
        }

        None
    }

    /// Get list of suspicious TAR values
    pub fn suspicious_tars() -> Vec<([u8; 3], &'static str)> {
        vec![
            ([0x00, 0x00, 0x00], "Wildcard TAR - targets all apps"),
            ([0xB0, 0xFF, 0xFF], "Suspicious RFM TAR"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_sms_pdu_type0() {
        // Simplified PDU with TP-PID = 0x40
        let pdu = vec![0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = OtaMonitor::analyze_sms_pdu(&pdu);
        assert_eq!(result, Some(OtaEventType::BinarySms));
    }

    #[test]
    fn test_parse_ota_command_sat() {
        // S@T Browser command structure
        let data = vec![0xD0, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = OtaMonitor::parse_ota_command(&data);
        assert_eq!(result, OtaEventType::SatBrowser);
    }

    #[test]
    fn test_authorized_source() {
        let mut monitor = OtaMonitor::new();
        monitor.add_authorized_source("+1234567890".to_string());

        assert!(monitor.is_authorized(&Some("+1234567890".to_string())));
        assert!(!monitor.is_authorized(&Some("+9999999999".to_string())));
        assert!(!monitor.is_authorized(&None));
    }

    #[test]
    fn test_simjacker_signature() {
        // S@T with PROVIDE LOCAL INFO - needs > 10 bytes
        let data = vec![0xD0, 0x10, 0x01, 0x02, 0x26, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let sig = OtaPatterns::check_signature(&data);
        assert!(sig.is_some());
        assert!(sig.unwrap().contains("Location"));
    }

    #[test]
    fn test_report_risk_level() {
        let report = OtaReport {
            total_events: 1,
            unauthorized: 0,
            binary_sms: 1,
            stk_pushes: 0,
            applet_installs: 0,
            file_modifications: 0,
            simjacker_attempts: 0,
            events: vec![],
        };
        assert_eq!(report.risk_level(), RiskLevel::Medium);

        let report_critical = OtaReport {
            simjacker_attempts: 1,
            ..report
        };
        assert_eq!(report_critical.risk_level(), RiskLevel::Critical);
    }
}
