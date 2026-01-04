//!
#![allow(dead_code, unused_imports, unused_variables)]
//! GentlyOS Network Security
//!
//! Cyberpunk visualization: Purple / Green / Aqua Blue
//! NO PEEKERS - locked engine, hardened core.
//!
//! # Modules
//!
//! - `firewall` - Software firewall with default-deny
//! - `monitor` - Network event logging and analysis
//! - `visualizer` - ASCII/SVG network maps
//! - `capture` - Packet capture (tshark/Wireshark CLI)
//! - `mitm` - MITM proxy (Burp Suite alternative)

pub mod firewall;
pub mod visualizer;
pub mod colors;
pub mod monitor;
pub mod capture;
pub mod mitm;

pub use firewall::{Firewall, FirewallRule, RuleAction};
pub use visualizer::NetworkVisualizer;
pub use monitor::{NetworkMonitor, NetworkEvent};
pub use capture::{PacketCapture, CaptureSession, Packet, filters, display_filters};
pub use mitm::{ProxyConfig, HttpRequest, HttpResponse, ProxyHistory, Repeater};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Network blocked: {0}")]
    Blocked(String),

    #[error("Connection denied: {0}")]
    Denied(String),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
