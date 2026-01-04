//! SIM Security Monitor
//!
//! Continuous monitoring of SIM state for security changes.

use crate::{
    SimBaseline, SimDiff, SimIdentity, SimFile, StkApplet, RiskLevel,
    filesystem::SimFilesystem,
    applet::AppletScanner,
    ota::OtaMonitor,
    apdu::ApduAnalyzer,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Complete SIM security monitor
pub struct SimMonitor {
    /// Current baseline
    baseline: Option<SimBaseline>,
    /// Filesystem scanner
    filesystem: SimFilesystem,
    /// Applet scanner
    applets: AppletScanner,
    /// OTA monitor
    ota: OtaMonitor,
    /// APDU analyzer
    apdu: ApduAnalyzer,
    /// Alert history
    alerts: Vec<SimAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimAlert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: SimAlertType,
    pub risk_level: RiskLevel,
    pub description: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SimAlertType {
    /// New file detected
    NewFile,
    /// File content changed
    FileModified,
    /// File deleted
    FileDeleted,
    /// New applet installed
    NewApplet,
    /// Applet removed
    AppletRemoved,
    /// OTA activity detected
    OtaActivity,
    /// Simjacker attack attempt
    SimjackerAttempt,
    /// Suspicious APDU pattern
    SuspiciousApdu,
    /// Unauthorized OTA source
    UnauthorizedOta,
    /// Baseline mismatch
    BaselineMismatch,
}

impl SimMonitor {
    pub fn new() -> Self {
        Self {
            baseline: None,
            filesystem: SimFilesystem::new(),
            applets: AppletScanner::new(),
            ota: OtaMonitor::new(),
            apdu: ApduAnalyzer::new(1000),
            alerts: Vec::new(),
        }
    }

    /// Create initial baseline from current SIM state
    pub fn create_baseline(&mut self, identity: SimIdentity) -> SimBaseline {
        let baseline = SimBaseline {
            created_at: Utc::now(),
            identity,
            files: self.filesystem.get_files().iter().cloned().cloned().collect(),
            applets: self.applets.get_applets().to_vec(),
            filesystem_hash: self.hash_filesystem(),
            applet_hash: self.hash_applets(),
        };

        self.baseline = Some(baseline.clone());
        baseline
    }

    /// Save baseline to file
    pub fn save_baseline(&self, path: &Path) -> std::io::Result<()> {
        if let Some(baseline) = &self.baseline {
            let json = serde_json::to_string_pretty(baseline)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    /// Load baseline from file
    pub fn load_baseline(&mut self, path: &Path) -> std::io::Result<()> {
        let json = std::fs::read_to_string(path)?;
        let baseline: SimBaseline = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        self.baseline = Some(baseline);
        Ok(())
    }

    /// Compare current state against baseline
    pub fn check_integrity(&mut self) -> Option<SimDiff> {
        let baseline = self.baseline.as_ref()?;

        let current = SimBaseline {
            created_at: Utc::now(),
            identity: baseline.identity.clone(),
            files: self.filesystem.get_files().iter().cloned().cloned().collect(),
            applets: self.applets.get_applets().to_vec(),
            filesystem_hash: self.hash_filesystem(),
            applet_hash: self.hash_applets(),
        };

        let diff = baseline.diff(&current);

        // Generate alerts for changes
        for file in &diff.new_files {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::NewFile,
                risk_level: RiskLevel::High,
                description: format!("New file detected: {}", file.fid),
                details: file.description.clone(),
            });
        }

        for file in &diff.deleted_files {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::FileDeleted,
                risk_level: RiskLevel::Medium,
                description: format!("File deleted: {}", file.fid),
                details: None,
            });
        }

        for (old, new) in &diff.modified_files {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::FileModified,
                risk_level: RiskLevel::High,
                description: format!("File modified: {}", new.fid),
                details: Some(format!("Old hash: {:?}, New hash: {:?}",
                    old.content_hash, new.content_hash)),
            });
        }

        for applet in &diff.new_applets {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::NewApplet,
                risk_level: RiskLevel::Critical,
                description: format!("New applet installed: {}",
                    applet.name.as_deref().unwrap_or(&applet.aid)),
                details: Some(format!("AID: {}, Privileges: {:?}",
                    applet.aid, applet.privileges)),
            });
        }

        Some(diff)
    }

    /// Add a file to the monitor
    pub fn add_file(&mut self, file: SimFile) {
        self.filesystem.add_file(file);
    }

    /// Add an applet to the monitor
    pub fn add_applet(&mut self, applet: StkApplet) {
        self.applets.add_applet(applet);
    }

    /// Record OTA event
    pub fn record_ota(&mut self, pdu: &[u8], source: Option<String>) {
        let event = self.ota.create_event(pdu, source);

        // Check for Simjacker
        if event.event_type == crate::OtaEventType::SatBrowser {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::SimjackerAttempt,
                risk_level: RiskLevel::Critical,
                description: "Possible Simjacker attack detected".to_string(),
                details: Some(format!("PDU hash: {}", event.pdu_hash)),
            });
        }

        // Check authorization
        if !event.authorized {
            self.add_alert(SimAlert {
                timestamp: Utc::now(),
                alert_type: SimAlertType::UnauthorizedOta,
                risk_level: RiskLevel::High,
                description: "Unauthorized OTA activity".to_string(),
                details: event.source.clone(),
            });
        }

        self.ota.record_event(event);
    }

    /// Add authorized OTA source
    pub fn add_authorized_ota_source(&mut self, source: String) {
        self.ota.add_authorized_source(source);
    }

    fn add_alert(&mut self, alert: SimAlert) {
        self.alerts.push(alert);
    }

    fn hash_filesystem(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for file in self.filesystem.get_files() {
            hasher.update(&file.fid);
            if let Some(hash) = &file.content_hash {
                hasher.update(hash);
            }
        }
        hex::encode(hasher.finalize())
    }

    fn hash_applets(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for applet in self.applets.get_applets() {
            hasher.update(&applet.aid);
        }
        hex::encode(hasher.finalize())
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[SimAlert] {
        &self.alerts
    }

    /// Get alerts by risk level
    pub fn get_critical_alerts(&self) -> Vec<&SimAlert> {
        self.alerts.iter()
            .filter(|a| a.risk_level == RiskLevel::Critical)
            .collect()
    }

    /// Generate comprehensive report
    pub fn generate_report(&self) -> MonitorReport {
        MonitorReport {
            timestamp: Utc::now(),
            baseline_created: self.baseline.as_ref().map(|b| b.created_at),
            total_files: self.filesystem.get_files().len(),
            total_applets: self.applets.get_applets().len(),
            total_alerts: self.alerts.len(),
            critical_alerts: self.get_critical_alerts().len(),
            ota_events: self.ota.get_events().len(),
            simjacker_vulnerable: self.applets.check_simjacker().len(),
            filesystem_report: self.filesystem.generate_report(),
            applet_report: self.applets.generate_report(),
            ota_report: self.ota.generate_report(),
            alerts: self.alerts.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorReport {
    pub timestamp: DateTime<Utc>,
    pub baseline_created: Option<DateTime<Utc>>,
    pub total_files: usize,
    pub total_applets: usize,
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub ota_events: usize,
    pub simjacker_vulnerable: usize,
    pub filesystem_report: crate::filesystem::SimScanReport,
    pub applet_report: crate::applet::AppletReport,
    pub ota_report: crate::ota::OtaReport,
    pub alerts: Vec<SimAlert>,
}

impl MonitorReport {
    pub fn print(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║           SIM SECURITY MONITOR REPORT                        ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Generated: {}                            ║", self.timestamp.format("%Y-%m-%d %H:%M:%S"));
        if let Some(baseline) = self.baseline_created {
            println!("║  Baseline:  {}                            ║", baseline.format("%Y-%m-%d %H:%M:%S"));
        }
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Files:     {:5}    Applets: {:5}                          ║",
            self.total_files, self.total_applets);
        println!("║  Alerts:    {:5}    Critical: {:5}                          ║",
            self.total_alerts, self.critical_alerts);
        println!("║  OTA Events: {:4}    Simjacker Risk: {:5}                   ║",
            self.ota_events, self.simjacker_vulnerable);
        println!("╚══════════════════════════════════════════════════════════════╝");

        self.filesystem_report.print();
        self.applet_report.print();
        self.ota_report.print();

        if !self.alerts.is_empty() {
            println!("\n  SECURITY ALERTS");
            println!("  ===============\n");
            for alert in &self.alerts {
                let icon = match alert.risk_level {
                    RiskLevel::Critical => "🔴",
                    RiskLevel::High => "🟠",
                    RiskLevel::Medium => "🟡",
                    RiskLevel::Low => "🟢",
                };
                println!("  {} [{:?}] {}", icon, alert.alert_type, alert.description);
                if let Some(details) = &alert.details {
                    println!("     Details: {}", details);
                }
            }
        }
    }

    pub fn overall_risk(&self) -> RiskLevel {
        if self.critical_alerts > 0 || self.simjacker_vulnerable > 0 {
            RiskLevel::Critical
        } else if self.total_alerts > 0 {
            RiskLevel::High
        } else if self.ota_events > 0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_new() {
        let monitor = SimMonitor::new();
        assert!(monitor.baseline.is_none());
        assert!(monitor.get_alerts().is_empty());
    }

    #[test]
    fn test_create_baseline() {
        let mut monitor = SimMonitor::new();

        let identity = SimIdentity {
            iccid: "1234567890".to_string(),
            imsi: Some("310260123456789".to_string()),
            mcc: Some("310".to_string()),
            mnc: Some("260".to_string()),
            spn: Some("T-Mobile".to_string()),
        };

        let baseline = monitor.create_baseline(identity);
        assert!(monitor.baseline.is_some());
        assert_eq!(baseline.identity.iccid, "1234567890");
    }

    #[test]
    fn test_alert_generation() {
        let mut monitor = SimMonitor::new();

        monitor.add_alert(SimAlert {
            timestamp: Utc::now(),
            alert_type: SimAlertType::NewApplet,
            risk_level: RiskLevel::Critical,
            description: "Test alert".to_string(),
            details: None,
        });

        assert_eq!(monitor.get_alerts().len(), 1);
        assert_eq!(monitor.get_critical_alerts().len(), 1);
    }

    #[test]
    fn test_report_risk_level() {
        let report = MonitorReport {
            timestamp: Utc::now(),
            baseline_created: None,
            total_files: 10,
            total_applets: 2,
            total_alerts: 0,
            critical_alerts: 0,
            ota_events: 0,
            simjacker_vulnerable: 0,
            filesystem_report: Default::default(),
            applet_report: crate::applet::AppletReport {
                total: 0,
                selectable: 0,
                known_carrier: 0,
                unknown: 0,
                high_risk: 0,
                simjacker_vulnerable: 0,
                applets: vec![],
            },
            ota_report: crate::ota::OtaReport {
                total_events: 0,
                unauthorized: 0,
                binary_sms: 0,
                stk_pushes: 0,
                applet_installs: 0,
                file_modifications: 0,
                simjacker_attempts: 0,
                events: vec![],
            },
            alerts: vec![],
        };

        assert_eq!(report.overall_risk(), RiskLevel::Low);
    }
}
