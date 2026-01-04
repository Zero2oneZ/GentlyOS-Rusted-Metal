//! Anti-Cheat Validation
//!
//! Prevents:
//! - Hardware spoofing
//! - Benchmark manipulation
//! - Contribution fraud
//! - Sybil attacks

use crate::{
    benchmark::{BenchmarkResult, GpuBenchmark},
    contribution::ContributionProof,
    hardware::HardwareProfile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Anti-cheat validation system
pub struct AntiCheatValidator {
    /// Known hardware fingerprints (for duplicate detection)
    known_fingerprints: Arc<RwLock<HashMap<[u8; 32], FingerprintRecord>>>,
    /// Performance history for anomaly detection
    performance_history: Arc<RwLock<Vec<PerformanceSnapshot>>>,
    /// Suspicious activity counter
    suspicion_score: Arc<RwLock<f64>>,
    /// Validation settings
    config: AntiCheatConfig,
}

#[derive(Debug, Clone)]
pub struct AntiCheatConfig {
    /// Max allowed benchmark variance (percentage)
    pub max_benchmark_variance: f64,
    /// Min tasks per epoch to validate
    pub min_tasks_per_epoch: u32,
    /// Max suspicion score before flagging
    pub max_suspicion_score: f64,
    /// Enable hardware fingerprint checking
    pub check_fingerprints: bool,
    /// Enable performance consistency checking
    pub check_performance: bool,
}

impl Default for AntiCheatConfig {
    fn default() -> Self {
        Self {
            max_benchmark_variance: 0.3, // 30%
            min_tasks_per_epoch: 1,
            max_suspicion_score: 10.0,
            check_fingerprints: true,
            check_performance: true,
        }
    }
}

#[derive(Debug, Clone)]
struct FingerprintRecord {
    first_seen: Instant,
    last_seen: Instant,
    occurrence_count: u64,
    associated_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct PerformanceSnapshot {
    timestamp: Instant,
    hash_rate: u64,
    inference_ms: Option<u64>,
    tasks_completed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub suspicion_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IssueSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IssueCategory {
    HardwareSpoof,
    BenchmarkManipulation,
    ContributionFraud,
    SybilAttack,
    PerformanceAnomaly,
    TimingAnomaly,
}

impl AntiCheatValidator {
    pub fn new() -> Self {
        Self::with_config(AntiCheatConfig::default())
    }

    pub fn with_config(config: AntiCheatConfig) -> Self {
        Self {
            known_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            performance_history: Arc::new(RwLock::new(Vec::new())),
            suspicion_score: Arc::new(RwLock::new(0.0)),
            config,
        }
    }

    /// Validate hardware claims against benchmark results
    pub fn validate_hardware(
        &self,
        hardware: &HardwareProfile,
        benchmark: &BenchmarkResult,
    ) -> ValidationReport {
        let mut issues = Vec::new();
        let mut suspicion = 0.0;

        // Check 1: CPU performance vs claimed cores
        let expected_min_hash = (hardware.cpu.cores as u64) * 400_000;
        let expected_max_hash = (hardware.cpu.cores as u64) * 2_000_000;

        if benchmark.cpu.hash_rate < expected_min_hash / 2 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::HardwareSpoof,
                description: format!(
                    "CPU hash rate {} too low for {} cores (expected >{})",
                    benchmark.cpu.hash_rate,
                    hardware.cpu.cores,
                    expected_min_hash / 2
                ),
            });
            suspicion += 5.0;
        } else if benchmark.cpu.hash_rate > expected_max_hash * 2 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::BenchmarkManipulation,
                description: format!(
                    "CPU hash rate {} suspiciously high for {} cores",
                    benchmark.cpu.hash_rate, hardware.cpu.cores
                ),
            });
            suspicion += 2.0;
        }

        // Check 2: Memory bandwidth vs claimed speed
        let expected_bandwidth = (hardware.memory.speed_mhz as u64) * 8 / 1000;
        if benchmark.memory.read_bandwidth < expected_bandwidth / 4 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::HardwareSpoof,
                description: format!(
                    "Memory bandwidth {} MB/s too low for {} MHz RAM",
                    benchmark.memory.read_bandwidth, hardware.memory.speed_mhz
                ),
            });
            suspicion += 2.0;
        }

        // Check 3: GPU performance (if claimed)
        if let (Some(hw_gpu), Some(bench_gpu)) = (&hardware.gpu, &benchmark.gpu) {
            self.validate_gpu(hw_gpu, bench_gpu, &mut issues, &mut suspicion);
        } else if hardware.gpu.is_some() && benchmark.gpu.is_none() {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::HardwareSpoof,
                description: "GPU claimed but no GPU benchmark results".to_string(),
            });
            suspicion += 5.0;
        }

        // Check 4: Proof-of-work validity
        if !self.verify_pow(&benchmark.proof) {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::BenchmarkManipulation,
                description: "Invalid proof-of-work in benchmark".to_string(),
            });
            suspicion += 10.0;
        }

        // Check 5: Timestamp freshness
        let now = chrono::Utc::now().timestamp();
        if (now - benchmark.timestamp).abs() > 600 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::TimingAnomaly,
                description: "Benchmark timestamp too old (>10 minutes)".to_string(),
            });
            suspicion += 1.0;
        }

        // Check 6: Fingerprint uniqueness
        if self.config.check_fingerprints {
            self.check_fingerprint_uniqueness(&hardware.fingerprint, &mut issues, &mut suspicion);
        }

        // Update global suspicion score
        {
            let mut score = self.suspicion_score.write().unwrap();
            *score = (*score * 0.9) + (suspicion * 0.1); // Exponential moving average
        }

        let recommendations = self.generate_recommendations(&issues);

        ValidationReport {
            valid: !issues.iter().any(|i| i.severity == IssueSeverity::Critical),
            issues,
            suspicion_score: suspicion,
            recommendations,
        }
    }

    fn validate_gpu(
        &self,
        hw_gpu: &crate::hardware::GpuInfo,
        bench_gpu: &GpuBenchmark,
        issues: &mut Vec<ValidationIssue>,
        suspicion: &mut f64,
    ) {
        // Expected inference time based on VRAM
        let expected_max_inference = match hw_gpu.vram_gb {
            0..=4 => 1000,
            5..=8 => 500,
            9..=12 => 200,
            13..=24 => 100,
            _ => 50,
        };

        if bench_gpu.inference_time_ms > expected_max_inference * 3 {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::HardwareSpoof,
                description: format!(
                    "GPU inference {}ms too slow for {} GB VRAM",
                    bench_gpu.inference_time_ms, hw_gpu.vram_gb
                ),
            });
            *suspicion += 2.0;
        }

        // Check TFLOPS reasonableness
        let expected_min_tflops = (hw_gpu.compute_units as f32) * 0.05;
        if bench_gpu.tflops < expected_min_tflops {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Info,
                category: IssueCategory::PerformanceAnomaly,
                description: format!(
                    "GPU TFLOPS {} lower than expected for {} compute units",
                    bench_gpu.tflops, hw_gpu.compute_units
                ),
            });
            *suspicion += 0.5;
        }
    }

    fn verify_pow(&self, proof: &crate::benchmark::BenchmarkProof) -> bool {
        // Recompute the hash
        let mut hasher = Sha256::new();
        hasher.update(&proof.result_hash);
        hasher.update(&proof.nonce.to_le_bytes());
        let computed: [u8; 32] = hasher.finalize().into();

        // Verify it matches
        if computed != proof.pow_hash {
            return false;
        }

        // Verify difficulty (2 leading zero bytes)
        proof.pow_hash[0] == 0 && proof.pow_hash[1] == 0
    }

    fn check_fingerprint_uniqueness(
        &self,
        fingerprint: &[u8; 32],
        issues: &mut Vec<ValidationIssue>,
        suspicion: &mut f64,
    ) {
        let mut known = self.known_fingerprints.write().unwrap();

        if let Some(record) = known.get_mut(fingerprint) {
            record.last_seen = Instant::now();
            record.occurrence_count += 1;

            if record.occurrence_count > 10 {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::SybilAttack,
                    description: format!(
                        "Hardware fingerprint seen {} times (possible Sybil)",
                        record.occurrence_count
                    ),
                });
                *suspicion += 3.0;
            }
        } else {
            known.insert(
                *fingerprint,
                FingerprintRecord {
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                    occurrence_count: 1,
                    associated_ips: Vec::new(),
                },
            );
        }
    }

    /// Validate contribution proof
    pub fn validate_contribution(&self, proof: &ContributionProof) -> bool {
        let mut issues = Vec::new();

        // Check 1: Non-zero work
        if proof.tasks_completed == 0 && proof.tasks_failed == 0 {
            tracing::debug!("Empty contribution proof");
            return true; // Empty but valid
        }

        // Check 2: Merkle root non-zero
        if proof.merkle_root == [0u8; 32] && proof.tasks_completed > 0 {
            tracing::warn!("Non-zero tasks but zero merkle root");
            issues.push(ValidationIssue {
                severity: IssueSeverity::Critical,
                category: IssueCategory::ContributionFraud,
                description: "Tasks completed but merkle root is zero".to_string(),
            });
        }

        // Check 3: Reasonable failure rate
        if proof.tasks_failed > proof.tasks_completed * 2 {
            tracing::warn!(
                "High failure rate: {} failed vs {} completed",
                proof.tasks_failed,
                proof.tasks_completed
            );
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::PerformanceAnomaly,
                description: "Unusually high failure rate".to_string(),
            });
        }

        // Check 4: Timing sanity
        if proof.tasks_completed > 0 && proof.inference_time_ms == 0 {
            // Could be all embeddings/storage, which is fine
        }

        // Check 5: Performance consistency
        if self.config.check_performance {
            self.check_performance_consistency(proof, &mut issues);
        }

        // Record performance snapshot
        {
            let mut history = self.performance_history.write().unwrap();
            history.push(PerformanceSnapshot {
                timestamp: Instant::now(),
                hash_rate: 0, // Not available in contribution proof
                inference_ms: Some(proof.inference_time_ms),
                tasks_completed: proof.tasks_completed,
            });

            // Keep only last 100 snapshots
            if history.len() > 100 {
                history.drain(0..50);
            }
        }

        !issues.iter().any(|i| i.severity == IssueSeverity::Critical)
    }

    fn check_performance_consistency(
        &self,
        proof: &ContributionProof,
        issues: &mut Vec<ValidationIssue>,
    ) {
        let history = self.performance_history.read().unwrap();

        if history.len() < 5 {
            return; // Not enough history
        }

        // Calculate average inference time
        let avg_inference: u64 = history
            .iter()
            .filter_map(|s| s.inference_ms)
            .sum::<u64>()
            / history.len().max(1) as u64;

        if avg_inference > 0 && proof.inference_time_ms > 0 {
            let variance =
                (proof.inference_time_ms as f64 - avg_inference as f64).abs() / avg_inference as f64;

            if variance > self.config.max_benchmark_variance {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Warning,
                    category: IssueCategory::PerformanceAnomaly,
                    description: format!(
                        "Inference time variance {:.1}% exceeds threshold",
                        variance * 100.0
                    ),
                });
            }
        }
    }

    fn generate_recommendations(&self, issues: &[ValidationIssue]) -> Vec<String> {
        let mut recs = Vec::new();

        for issue in issues {
            match issue.category {
                IssueCategory::HardwareSpoof => {
                    recs.push("Verify hardware detection is accurate".to_string());
                    recs.push("Run benchmark with no other processes".to_string());
                }
                IssueCategory::BenchmarkManipulation => {
                    recs.push("Re-run benchmark with fresh start".to_string());
                }
                IssueCategory::PerformanceAnomaly => {
                    recs.push("Check for thermal throttling".to_string());
                    recs.push("Ensure stable power supply".to_string());
                }
                IssueCategory::SybilAttack => {
                    recs.push("Each device should have unique hardware".to_string());
                }
                IssueCategory::TimingAnomaly => {
                    recs.push("Ensure system clock is synchronized".to_string());
                }
                _ => {}
            }
        }

        recs.sort();
        recs.dedup();
        recs
    }

    /// Get current suspicion score
    pub fn suspicion_score(&self) -> f64 {
        *self.suspicion_score.read().unwrap()
    }

    /// Check if node should be flagged
    pub fn should_flag(&self) -> bool {
        self.suspicion_score() > self.config.max_suspicion_score
    }

    /// Reset suspicion score
    pub fn reset_suspicion(&self) {
        *self.suspicion_score.write().unwrap() = 0.0;
    }

    /// Detect potential VM/emulation
    pub fn detect_virtualization(&self, hardware: &HardwareProfile) -> Option<String> {
        let model = hardware.cpu.model.to_lowercase();

        // Common VM indicators
        if model.contains("qemu") {
            return Some("QEMU virtualization detected".to_string());
        }
        if model.contains("virtual") {
            return Some("Virtual CPU detected".to_string());
        }
        if model.contains("kvm") {
            return Some("KVM virtualization detected".to_string());
        }

        // Check for suspiciously round numbers
        if hardware.memory.total_gb % 4 == 0 && hardware.cpu.cores % 2 == 0 {
            // Could be VM with standard allocations, but not definitive
        }

        None
    }
}

impl Default for AntiCheatValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_cheat_validator() {
        let validator = AntiCheatValidator::new();

        assert_eq!(validator.suspicion_score(), 0.0);
        assert!(!validator.should_flag());
    }

    #[test]
    fn test_contribution_validation() {
        let validator = AntiCheatValidator::new();

        let proof = ContributionProof {
            epoch: 1,
            tasks_completed: 10,
            tasks_failed: 1,
            inference_time_ms: 1000,
            embeddings_created: 5,
            storage_served_mb: 2,
            merkle_root: [1u8; 32],
            signature: [0u8; 64].to_vec(),
            alexandria_edges_served: 0,
            alexandria_deltas_synced: 0,
            alexandria_wormholes_found: 0,
        };

        assert!(validator.validate_contribution(&proof));
    }

    #[test]
    fn test_empty_contribution() {
        let validator = AntiCheatValidator::new();

        let proof = ContributionProof {
            epoch: 1,
            tasks_completed: 0,
            tasks_failed: 0,
            inference_time_ms: 0,
            embeddings_created: 0,
            storage_served_mb: 0,
            merkle_root: [0u8; 32],
            signature: [0u8; 64].to_vec(),
            alexandria_edges_served: 0,
            alexandria_deltas_synced: 0,
            alexandria_wormholes_found: 0,
        };

        assert!(validator.validate_contribution(&proof));
    }
}

// Re-export ContributionProof for this module
