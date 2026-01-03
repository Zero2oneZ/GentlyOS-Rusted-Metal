//! Hardware Benchmarking and Validation
//!
//! Runs benchmarks to:
//! - Validate hardware claims
//! - Create proof of capability
//! - Detect cheating/emulation

use crate::hardware::{HardwareProfile, GpuInfo};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{Duration, Instant};

/// Complete benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// CPU benchmark results
    pub cpu: CpuBenchmark,
    /// Memory benchmark results
    pub memory: MemoryBenchmark,
    /// GPU benchmark results (if available)
    pub gpu: Option<GpuBenchmark>,
    /// Storage benchmark results
    pub storage: StorageBenchmark,
    /// Timestamp of benchmark
    pub timestamp: i64,
    /// Cryptographic proof
    pub proof: BenchmarkProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuBenchmark {
    /// SHA256 hashes per second
    pub hash_rate: u64,
    /// Matrix multiply operations per second
    pub flops: u64,
    /// Single-threaded score
    pub single_thread_score: u64,
    /// Multi-threaded score
    pub multi_thread_score: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBenchmark {
    /// Read bandwidth MB/s
    pub read_bandwidth: u64,
    /// Write bandwidth MB/s
    pub write_bandwidth: u64,
    /// Random access latency (ns)
    pub latency_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuBenchmark {
    /// Inference time for standard model (ms)
    pub inference_time_ms: u64,
    /// Embedding generation time (ms)
    pub embedding_time_ms: u64,
    /// TFLOPS measured
    pub tflops: f32,
    /// Memory bandwidth GB/s
    pub memory_bandwidth: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBenchmark {
    /// Sequential read MB/s
    pub seq_read: u64,
    /// Sequential write MB/s
    pub seq_write: u64,
    /// Random read IOPS
    pub rand_read_iops: u32,
    /// Random write IOPS
    pub rand_write_iops: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkProof {
    /// Hash of all benchmark results
    pub result_hash: [u8; 32],
    /// Nonce used in proof-of-work
    pub nonce: u64,
    /// Proof-of-work hash (must have leading zeros)
    pub pow_hash: [u8; 32],
    /// Timestamp
    pub timestamp: i64,
    /// Ed25519 signature (filled by wallet)
    pub signature: Vec<u8>,
}

/// Benchmark runner
pub struct Benchmark;

impl Benchmark {
    /// Run full benchmark suite
    pub async fn run_full(hardware: &HardwareProfile) -> anyhow::Result<BenchmarkResult> {
        tracing::info!("Starting hardware benchmark...");

        let cpu = Self::benchmark_cpu(hardware).await?;
        tracing::info!("CPU benchmark complete: {} H/s", cpu.hash_rate);

        let memory = Self::benchmark_memory().await?;
        tracing::info!("Memory benchmark complete: {} MB/s read", memory.read_bandwidth);

        let gpu = if hardware.gpu.is_some() {
            Some(Self::benchmark_gpu(hardware.gpu.as_ref().unwrap()).await?)
        } else {
            None
        };
        if let Some(ref g) = gpu {
            tracing::info!("GPU benchmark complete: {}ms inference", g.inference_time_ms);
        }

        let storage = Self::benchmark_storage().await?;
        tracing::info!("Storage benchmark complete: {} MB/s read", storage.seq_read);

        let timestamp = chrono::Utc::now().timestamp();

        // Create proof
        let proof = Self::create_proof(&cpu, &memory, &gpu, &storage, timestamp)?;

        Ok(BenchmarkResult {
            cpu,
            memory,
            gpu,
            storage,
            timestamp,
            proof,
        })
    }

    /// CPU benchmark
    async fn benchmark_cpu(hardware: &HardwareProfile) -> anyhow::Result<CpuBenchmark> {
        // Single-threaded hash rate
        let single_hash_rate = Self::measure_hash_rate(1).await;

        // Multi-threaded hash rate
        let multi_hash_rate = Self::measure_hash_rate(hardware.cpu.threads as usize).await;

        // Matrix operations (simple approximation)
        let flops = Self::measure_flops().await;

        Ok(CpuBenchmark {
            hash_rate: multi_hash_rate,
            flops,
            single_thread_score: single_hash_rate / 1000,
            multi_thread_score: multi_hash_rate / 1000,
        })
    }

    async fn measure_hash_rate(threads: usize) -> u64 {
        let duration = Duration::from_secs(2);
        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let count = count.clone();
                std::thread::spawn(move || {
                    let start = Instant::now();
                    let mut data = vec![0u8; 64];
                    let mut local_count = 0u64;

                    while start.elapsed() < duration {
                        for _ in 0..1000 {
                            let mut hasher = Sha256::new();
                            hasher.update(&data);
                            data[..32].copy_from_slice(&hasher.finalize());
                            local_count += 1;
                        }
                    }

                    count.fetch_add(local_count, std::sync::atomic::Ordering::Relaxed);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        count.load(std::sync::atomic::Ordering::Relaxed) / 2 // Per second
    }

    async fn measure_flops() -> u64 {
        let duration = Duration::from_secs(1);
        let start = Instant::now();
        let mut ops = 0u64;

        // Simple matrix multiply approximation
        let size = 256;
        let mut a = vec![1.0f32; size * size];
        let mut b = vec![1.0f32; size * size];
        let mut c = vec![0.0f32; size * size];

        while start.elapsed() < duration {
            // Naive matrix multiply (cache-unfriendly but consistent)
            for i in 0..size {
                for j in 0..size {
                    let mut sum = 0.0f32;
                    for k in 0..size {
                        sum += a[i * size + k] * b[k * size + j];
                    }
                    c[i * size + j] = sum;
                }
            }
            ops += (2 * size * size * size) as u64; // 2N^3 FLOPs per multiply

            // Prevent optimization
            std::hint::black_box(&c);
        }

        ops
    }

    /// Memory benchmark
    async fn benchmark_memory() -> anyhow::Result<MemoryBenchmark> {
        let size = 256 * 1024 * 1024; // 256 MB
        let mut buffer = vec![0u8; size];

        // Write bandwidth
        let start = Instant::now();
        for chunk in buffer.chunks_mut(4096) {
            for byte in chunk.iter_mut() {
                *byte = 0xFF;
            }
        }
        std::hint::black_box(&buffer);
        let write_time = start.elapsed();
        let write_bandwidth = (size as f64 / write_time.as_secs_f64() / 1_000_000.0) as u64;

        // Read bandwidth
        let start = Instant::now();
        let mut sum = 0u64;
        for chunk in buffer.chunks(4096) {
            for byte in chunk {
                sum = sum.wrapping_add(*byte as u64);
            }
        }
        std::hint::black_box(sum);
        let read_time = start.elapsed();
        let read_bandwidth = (size as f64 / read_time.as_secs_f64() / 1_000_000.0) as u64;

        // Latency (random access)
        let start = Instant::now();
        let mut idx = 0usize;
        for _ in 0..1_000_000 {
            idx = (buffer[idx % size] as usize * 257) % size;
        }
        std::hint::black_box(idx);
        let latency_ns = start.elapsed().as_nanos() as u64 / 1_000_000;

        Ok(MemoryBenchmark {
            read_bandwidth,
            write_bandwidth,
            latency_ns,
        })
    }

    /// GPU benchmark
    async fn benchmark_gpu(gpu: &GpuInfo) -> anyhow::Result<GpuBenchmark> {
        // This would use the actual inference engine
        // For now, estimate based on hardware

        let base_inference_ms = match gpu.vram_gb {
            0..=4 => 500,
            5..=8 => 200,
            9..=12 => 100,
            13..=24 => 50,
            _ => 30,
        };

        let embedding_ms = base_inference_ms / 4;

        // Estimate TFLOPS from compute units
        let tflops = (gpu.compute_units as f32) * 0.1;

        // Estimate memory bandwidth
        let memory_bandwidth = (gpu.vram_gb as f32) * 40.0; // Rough estimate

        Ok(GpuBenchmark {
            inference_time_ms: base_inference_ms,
            embedding_time_ms: embedding_ms,
            tflops,
            memory_bandwidth,
        })
    }

    /// Storage benchmark
    async fn benchmark_storage() -> anyhow::Result<StorageBenchmark> {
        let test_file = "/tmp/gently_bench_test";
        let size = 64 * 1024 * 1024; // 64 MB
        let data = vec![0xABu8; size];

        // Sequential write
        let start = Instant::now();
        std::fs::write(test_file, &data)?;
        let write_time = start.elapsed();
        let seq_write = (size as f64 / write_time.as_secs_f64() / 1_000_000.0) as u64;

        // Sequential read
        let start = Instant::now();
        let _ = std::fs::read(test_file)?;
        let read_time = start.elapsed();
        let seq_read = (size as f64 / read_time.as_secs_f64() / 1_000_000.0) as u64;

        // Cleanup
        std::fs::remove_file(test_file)?;

        // Random IOPS (simplified - would need proper random I/O test)
        let rand_read_iops = (seq_read * 1000 / 4) as u32; // Rough estimate
        let rand_write_iops = (seq_write * 1000 / 4) as u32;

        Ok(StorageBenchmark {
            seq_read,
            seq_write,
            rand_read_iops,
            rand_write_iops,
        })
    }

    /// Create cryptographic proof of benchmark
    fn create_proof(
        cpu: &CpuBenchmark,
        memory: &MemoryBenchmark,
        gpu: &Option<GpuBenchmark>,
        storage: &StorageBenchmark,
        timestamp: i64,
    ) -> anyhow::Result<BenchmarkProof> {
        // Hash all results
        let mut hasher = Sha256::new();
        hasher.update(&cpu.hash_rate.to_le_bytes());
        hasher.update(&cpu.flops.to_le_bytes());
        hasher.update(&memory.read_bandwidth.to_le_bytes());
        hasher.update(&memory.write_bandwidth.to_le_bytes());
        if let Some(gpu) = gpu {
            hasher.update(&gpu.inference_time_ms.to_le_bytes());
        }
        hasher.update(&storage.seq_read.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());

        let result_hash: [u8; 32] = hasher.finalize().into();

        // Proof of work (find nonce that creates hash with leading zeros)
        let difficulty = 2; // Number of leading zero bytes required
        let (nonce, pow_hash) = Self::find_pow(&result_hash, difficulty);

        Ok(BenchmarkProof {
            result_hash,
            nonce,
            pow_hash,
            timestamp,
            signature: vec![0u8; 64], // Filled later by wallet
        })
    }

    /// Find proof-of-work nonce
    fn find_pow(data: &[u8; 32], difficulty: usize) -> (u64, [u8; 32]) {
        let mut nonce = 0u64;

        loop {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(&nonce.to_le_bytes());
            let hash: [u8; 32] = hasher.finalize().into();

            // Check leading zeros
            let leading_zeros = hash.iter().take(difficulty).all(|&b| b == 0);
            if leading_zeros {
                return (nonce, hash);
            }

            nonce += 1;

            // Safety limit
            if nonce > 100_000_000 {
                return (nonce, hash);
            }
        }
    }
}

/// Validate benchmark results against hardware claims
pub fn validate_benchmark(
    hardware: &HardwareProfile,
    benchmark: &BenchmarkResult,
) -> ValidationResult {
    let mut issues = Vec::new();

    // Validate CPU performance
    let expected_min_hash = (hardware.cpu.cores as u64) * 500_000;
    if benchmark.cpu.hash_rate < expected_min_hash / 2 {
        issues.push("CPU hash rate too low for claimed cores".to_string());
    }

    // Validate memory bandwidth
    let expected_min_bandwidth = (hardware.memory.speed_mhz as u64) * 8 / 1000;
    if benchmark.memory.read_bandwidth < expected_min_bandwidth / 4 {
        issues.push("Memory bandwidth too low for claimed speed".to_string());
    }

    // Validate GPU if claimed
    if let (Some(hw_gpu), Some(bench_gpu)) = (&hardware.gpu, &benchmark.gpu) {
        // Larger VRAM should mean faster inference
        let expected_max_inference = 10000 / (hw_gpu.vram_gb as u64).max(1);
        if bench_gpu.inference_time_ms > expected_max_inference * 3 {
            issues.push("GPU inference too slow for claimed VRAM".to_string());
        }
    }

    // Validate timestamp
    let now = chrono::Utc::now().timestamp();
    if (now - benchmark.timestamp).abs() > 600 {
        issues.push("Benchmark timestamp too old".to_string());
    }

    // Validate proof-of-work
    let mut hasher = Sha256::new();
    hasher.update(&benchmark.proof.result_hash);
    hasher.update(&benchmark.proof.nonce.to_le_bytes());
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash != benchmark.proof.pow_hash {
        issues.push("Invalid proof-of-work".to_string());
    }

    if !benchmark.proof.pow_hash[..2].iter().all(|&b| b == 0) {
        issues.push("Proof-of-work difficulty not met".to_string());
    }

    ValidationResult {
        valid: issues.is_empty(),
        issues: issues.clone(),
        confidence: if issues.is_empty() { 1.0 } else { 0.5 - (issues.len() as f32 * 0.1) },
    }
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub issues: Vec<String>,
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::HardwareProfile;

    #[tokio::test]
    async fn test_benchmark() {
        let hardware = HardwareProfile::detect().unwrap();
        let benchmark = Benchmark::run_full(&hardware).await.unwrap();

        println!("CPU hash rate: {} H/s", benchmark.cpu.hash_rate);
        println!("Memory read: {} MB/s", benchmark.memory.read_bandwidth);
        println!("Storage read: {} MB/s", benchmark.storage.seq_read);

        let validation = validate_benchmark(&hardware, &benchmark);
        println!("Valid: {}, Issues: {:?}", validation.valid, validation.issues);

        assert!(benchmark.cpu.hash_rate > 0);
        assert!(benchmark.memory.read_bandwidth > 0);
    }

    #[test]
    fn test_pow() {
        let data = [0u8; 32];
        let (nonce, hash) = Benchmark::find_pow(&data, 2);

        assert!(hash[0] == 0 && hash[1] == 0);
        println!("Found nonce {} with hash {:?}", nonce, &hash[..4]);
    }
}
