//! Token Distiller
//!
//! Detects and neutralizes token/credential leakage in prompts and responses.
//! Prevents API keys, passwords, and other secrets from being exposed.

use regex::Regex;
use std::collections::HashMap;

/// Token distiller - detects and masks sensitive tokens
pub struct TokenDistiller {
    /// Token patterns to detect
    patterns: Vec<TokenPattern>,
    /// Token statistics
    stats: DistillerStats,
    /// Action on detection
    action: DistillerAction,
}

impl TokenDistiller {
    /// Create new distiller with default patterns
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
            stats: DistillerStats::default(),
            action: DistillerAction::MaskAndWarn,
        }
    }

    /// Add custom pattern
    pub fn add_pattern(mut self, pattern: TokenPattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    /// Set action on detection
    pub fn action(mut self, action: DistillerAction) -> Self {
        self.action = action;
        self
    }

    /// Distill tokens from text (detect and optionally mask)
    pub fn distill(&mut self, text: &str) -> DistillResult {
        let mut tokens = Vec::new();
        let mut masked_text = text.to_string();

        for pattern in &self.patterns {
            if let Ok(regex) = Regex::new(&pattern.regex) {
                for cap in regex.captures_iter(text) {
                    if let Some(matched) = cap.get(0) {
                        let token = DistilledToken {
                            token_type: pattern.token_type.clone(),
                            value: matched.as_str().to_string(),
                            position: matched.start(),
                            length: matched.len(),
                            risk_level: pattern.risk_level,
                        };

                        // Mask in text
                        let mask = self.generate_mask(&token);
                        masked_text = masked_text.replace(matched.as_str(), &mask);

                        tokens.push(token);
                        self.stats.tokens_detected += 1;
                    }
                }
            }
        }

        let action_taken = if tokens.is_empty() { None } else { Some(self.action) };

        if !tokens.is_empty() {
            self.stats.distill_operations += 1;
        }

        DistillResult {
            original: text.to_string(),
            masked: masked_text,
            tokens,
            action_taken,
        }
    }

    /// Check if text contains any sensitive tokens
    pub fn contains_sensitive(&self, text: &str) -> bool {
        for pattern in &self.patterns {
            if let Ok(regex) = Regex::new(&pattern.regex) {
                if regex.is_match(text) {
                    return true;
                }
            }
        }
        false
    }

    /// Get statistics
    pub fn stats(&self) -> &DistillerStats {
        &self.stats
    }

    /// Generate mask for a token
    fn generate_mask(&self, token: &DistilledToken) -> String {
        let type_hint = match &token.token_type {
            TokenType::ApiKey => "[API_KEY_REDACTED]",
            TokenType::Password => "[PASSWORD_REDACTED]",
            TokenType::BearerToken => "[BEARER_TOKEN_REDACTED]",
            TokenType::JwtToken => "[JWT_REDACTED]",
            TokenType::PrivateKey => "[PRIVATE_KEY_REDACTED]",
            TokenType::SshKey => "[SSH_KEY_REDACTED]",
            TokenType::AwsKey => "[AWS_KEY_REDACTED]",
            TokenType::GcpKey => "[GCP_KEY_REDACTED]",
            TokenType::DatabaseUrl => "[DATABASE_URL_REDACTED]",
            TokenType::CryptoSeed => "[CRYPTO_SEED_REDACTED]",
            TokenType::Custom(name) => return format!("[{}_REDACTED]", name.to_uppercase()),
        };
        type_hint.to_string()
    }

    /// Default token patterns
    fn default_patterns() -> Vec<TokenPattern> {
        vec![
            // API Keys
            TokenPattern {
                name: "Anthropic API Key".to_string(),
                regex: r"sk-ant-[a-zA-Z0-9\-_]{40,}".to_string(),
                token_type: TokenType::ApiKey,
                risk_level: RiskLevel::Critical,
            },
            TokenPattern {
                name: "OpenAI API Key".to_string(),
                regex: r"sk-[a-zA-Z0-9]{48,}".to_string(),
                token_type: TokenType::ApiKey,
                risk_level: RiskLevel::Critical,
            },
            TokenPattern {
                name: "Generic API Key".to_string(),
                regex: r#"(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?"#.to_string(),
                token_type: TokenType::ApiKey,
                risk_level: RiskLevel::High,
            },
            // Bearer Tokens
            TokenPattern {
                name: "Bearer Token".to_string(),
                regex: r"Bearer\s+[a-zA-Z0-9\-_\.]+".to_string(),
                token_type: TokenType::BearerToken,
                risk_level: RiskLevel::High,
            },
            // JWT Tokens
            TokenPattern {
                name: "JWT Token".to_string(),
                regex: r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+".to_string(),
                token_type: TokenType::JwtToken,
                risk_level: RiskLevel::High,
            },
            // AWS Keys
            TokenPattern {
                name: "AWS Access Key".to_string(),
                regex: r"AKIA[0-9A-Z]{16}".to_string(),
                token_type: TokenType::AwsKey,
                risk_level: RiskLevel::Critical,
            },
            TokenPattern {
                name: "AWS Secret Key".to_string(),
                regex: r#"(?i)aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9/\+=]{40})['"]?"#.to_string(),
                token_type: TokenType::AwsKey,
                risk_level: RiskLevel::Critical,
            },
            // Private Keys
            TokenPattern {
                name: "RSA Private Key".to_string(),
                regex: r"-----BEGIN RSA PRIVATE KEY-----".to_string(),
                token_type: TokenType::PrivateKey,
                risk_level: RiskLevel::Critical,
            },
            TokenPattern {
                name: "EC Private Key".to_string(),
                regex: r"-----BEGIN EC PRIVATE KEY-----".to_string(),
                token_type: TokenType::PrivateKey,
                risk_level: RiskLevel::Critical,
            },
            // SSH Keys
            TokenPattern {
                name: "SSH Private Key".to_string(),
                regex: r"-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                token_type: TokenType::SshKey,
                risk_level: RiskLevel::Critical,
            },
            // Passwords in common formats
            TokenPattern {
                name: "Password in URL".to_string(),
                regex: r"://[^:]+:([^@]+)@".to_string(),
                token_type: TokenType::Password,
                risk_level: RiskLevel::High,
            },
            TokenPattern {
                name: "Password Assignment".to_string(),
                regex: r#"(?i)(password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s'"]{8,})['"]?"#.to_string(),
                token_type: TokenType::Password,
                risk_level: RiskLevel::High,
            },
            // Database URLs
            TokenPattern {
                name: "Database URL".to_string(),
                regex: r"(?i)(postgres|mysql|mongodb|redis)://[^\s]+".to_string(),
                token_type: TokenType::DatabaseUrl,
                risk_level: RiskLevel::High,
            },
            // Crypto Seeds/Mnemonics
            TokenPattern {
                name: "Crypto Mnemonic".to_string(),
                regex: r#"(?i)(seed|mnemonic)['"]?\s*[:=]\s*['"]?(\w+(?:\s+\w+){11,23})['"]?"#.to_string(),
                token_type: TokenType::CryptoSeed,
                risk_level: RiskLevel::Critical,
            },
        ]
    }
}

impl Default for TokenDistiller {
    fn default() -> Self {
        Self::new()
    }
}

/// Token pattern definition
#[derive(Debug, Clone)]
pub struct TokenPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern
    pub regex: String,
    /// Token type
    pub token_type: TokenType,
    /// Risk level
    pub risk_level: RiskLevel,
}

/// Types of tokens
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    ApiKey,
    Password,
    BearerToken,
    JwtToken,
    PrivateKey,
    SshKey,
    AwsKey,
    GcpKey,
    DatabaseUrl,
    CryptoSeed,
    Custom(String),
}

/// Risk level of detected token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected token
#[derive(Debug, Clone)]
pub struct DistilledToken {
    /// Type of token
    pub token_type: TokenType,
    /// Original value (for logging, should be masked in production)
    pub value: String,
    /// Position in text
    pub position: usize,
    /// Length of token
    pub length: usize,
    /// Risk level
    pub risk_level: RiskLevel,
}

/// Result of distillation
#[derive(Debug, Clone)]
pub struct DistillResult {
    /// Original text
    pub original: String,
    /// Masked text
    pub masked: String,
    /// Detected tokens
    pub tokens: Vec<DistilledToken>,
    /// Action taken
    pub action_taken: Option<DistillerAction>,
}

impl DistillResult {
    /// Check if any tokens were detected
    pub fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Get count of tokens by risk level
    pub fn count_by_risk(&self, level: RiskLevel) -> usize {
        self.tokens.iter().filter(|t| t.risk_level == level).count()
    }

    /// Get highest risk level found
    pub fn highest_risk(&self) -> Option<RiskLevel> {
        self.tokens.iter()
            .map(|t| t.risk_level)
            .max_by_key(|r| match r {
                RiskLevel::Critical => 4,
                RiskLevel::High => 3,
                RiskLevel::Medium => 2,
                RiskLevel::Low => 1,
            })
    }
}

/// Action to take on detection
#[derive(Debug, Clone, Copy)]
pub enum DistillerAction {
    /// Just detect, don't modify
    DetectOnly,
    /// Mask and log warning
    MaskAndWarn,
    /// Mask and block request
    MaskAndBlock,
    /// Block request without masking
    BlockImmediately,
}

/// Distiller statistics
#[derive(Debug, Clone, Default)]
pub struct DistillerStats {
    /// Total tokens detected
    pub tokens_detected: usize,
    /// Total distill operations
    pub distill_operations: usize,
    /// Tokens by type
    pub by_type: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_api_key() {
        let mut distiller = TokenDistiller::new();
        let text = "My API key is sk-ant-abc123def456ghi789jkl012mno345pqr678stu901";
        let result = distiller.distill(text);

        assert!(result.has_tokens());
        assert!(result.tokens.iter().any(|t| matches!(t.token_type, TokenType::ApiKey)));
    }

    #[test]
    fn test_detect_jwt() {
        let mut distiller = TokenDistiller::new();
        let text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = distiller.distill(text);

        assert!(result.has_tokens());
        assert!(result.tokens.iter().any(|t| matches!(t.token_type, TokenType::JwtToken)));
    }

    #[test]
    fn test_mask_tokens() {
        let mut distiller = TokenDistiller::new();
        let text = "Bearer abc123secret456token789";
        let result = distiller.distill(text);

        assert!(result.masked.contains("[BEARER_TOKEN_REDACTED]"));
        assert!(!result.masked.contains("abc123"));
    }

    #[test]
    fn test_no_false_positives() {
        let mut distiller = TokenDistiller::new();
        let text = "Hello, this is a normal message without any secrets.";
        let result = distiller.distill(text);

        assert!(!result.has_tokens());
        assert_eq!(result.original, result.masked);
    }
}
