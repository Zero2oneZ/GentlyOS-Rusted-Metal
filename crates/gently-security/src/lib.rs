//!
#![allow(dead_code, unused_imports, unused_variables)]
//! GentlyOS Security Layer
//!
//! "IT'S DEFINITELY ATTACKING YOUR COMPUTER"
//!
//! Core security components:
//! - TokenDistiller: Detect and neutralize token leakage
//! - RateLimiter: 5-layer rate limiting
//! - ThreatDetector: Jailbreak/injection detection
//! - TrustSystem: Assume-hostile trust management
//! - HoneypotSystem: AI-irresistible traps
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    SECURITY LAYER                                   │
//! │                                                                     │
//! │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
//! │   │   TOKEN      │  │    RATE      │  │   THREAT     │            │
//! │   │  DISTILLER   │  │   LIMITER    │  │  DETECTOR    │            │
//! │   └──────────────┘  └──────────────┘  └──────────────┘            │
//! │          │                 │                 │                     │
//! │          └────────────┬────┴────────────────┘                     │
//! │                       │                                           │
//! │              ┌────────▼────────┐                                  │
//! │              │  SECURITY       │                                  │
//! │              │  CONTROLLER     │                                  │
//! │              └─────────────────┘                                  │
//! │                       │                                           │
//! │   ┌───────────────────┼───────────────────┐                      │
//! │   ▼                   ▼                   ▼                      │
//! │ TRUST              HONEYPOT           THREAT                     │
//! │ SYSTEM             SYSTEM             INTEL                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

pub mod distiller;
pub mod limiter;
pub mod detector;
pub mod trust;
pub mod honeypot;
pub mod controller;
pub mod daemons;
pub mod agentic;
pub mod fafo;

pub use distiller::{TokenDistiller, TokenType, DistilledToken};
pub use limiter::{RateLimiter, RateLimitLayer, RateLimitResult};
pub use detector::{ThreatDetector, ThreatType, ThreatLevel, Detection};
pub use trust::{TrustSystem, TrustLevel, TrustState};
pub use honeypot::{HoneypotSystem, Honeypot, HoneypotType};
pub use controller::{SecurityController, DefenseMode, SecurityEvent};
pub use daemons::*;
pub use agentic::AgenticSecurityController;
pub use fafo::{FafoController, FafoMode, FafoResponse, FafoStats, PoisonPayload, SamsonConfig};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Threat detected: {0}")]
    ThreatDetected(String),

    #[error("Trust violation: {0}")]
    TrustViolation(String),

    #[error("Token leaked: {0}")]
    TokenLeaked(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),
}

pub type Result<T> = std::result::Result<T, SecurityError>;

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable token distilling
    pub distill_tokens: bool,
    /// Enable rate limiting
    pub rate_limiting: bool,
    /// Enable threat detection
    pub threat_detection: bool,
    /// Enable trust system
    pub trust_system: bool,
    /// Enable honeypots
    pub honeypots: bool,
    /// Defense mode
    pub defense_mode: DefenseMode,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            distill_tokens: true,
            rate_limiting: true,
            threat_detection: true,
            trust_system: true,
            honeypots: true,
            defense_mode: DefenseMode::Normal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert!(config.distill_tokens);
        assert!(config.rate_limiting);
        assert!(config.threat_detection);
    }
}
