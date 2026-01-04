//! Hardware Detection and Profiling
//!
//! Detects system hardware for:
//! - Scoring contribution capacity
//! - Validating benchmark results
//! - Creating hardware fingerprint

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::process::Command;

/// Complete hardware profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// CPU information
    pub cpu: CpuInfo,
    /// Memory information
    pub memory: MemoryInfo,
    /// GPU information (if available)
    pub gpu: Option<GpuInfo>,
    /// Storage information
    pub storage: StorageInfo,
    /// Network information
    pub network: NetworkInfo,
    /// Unique hardware fingerprint
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub vendor: String,
    pub model: String,
    pub cores: u8,
    pub threads: u8,
    pub base_freq_mhz: u32,
    pub max_freq_mhz: u32,
    pub cache_kb: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_gb: u16,
    pub available_gb: u16,
    pub speed_mhz: u16,
    pub channels: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: String,
    pub model: String,
    pub vram_gb: u16,
    pub compute_units: u16,
    pub driver_version: String,
    pub cuda_version: Option<String>,
    pub rocm_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub total_gb: u32,
    pub available_gb: u32,
    pub is_ssd: bool,
    pub read_speed_mbps: u32,
    pub write_speed_mbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub download_mbps: u32,
    pub upload_mbps: u32,
    pub latency_ms: u16,
}

impl HardwareProfile {
    /// Detect hardware on current system
    pub fn detect() -> anyhow::Result<Self> {
        let cpu = detect_cpu()?;
        let memory = detect_memory()?;
        let gpu = detect_gpu();
        let storage = detect_storage()?;
        let network = detect_network()?;

        // Create fingerprint from hardware IDs
        let fingerprint = create_fingerprint(&cpu, &memory, &gpu, &storage);

        Ok(Self {
            cpu,
            memory,
            gpu,
            storage,
            network,
            fingerprint,
        })
    }

    /// Calculate hardware score for reward calculation
    pub fn calculate_score(&self) -> u64 {
        let mut score: u64 = 0;

        // CPU: 1 point per core, 0.5 per thread
        score += self.cpu.cores as u64;
        score += (self.cpu.threads as u64) / 2;

        // RAM: 1 point per 4GB
        score += (self.memory.total_gb as u64) / 4;

        // GPU: 5 points per GB VRAM
        if let Some(ref gpu) = self.gpu {
            score += (gpu.vram_gb as u64) * 5;
        }

        // Storage: 1 point per 100GB (SSD bonus)
        score += (self.storage.total_gb as u64) / 100;
        if self.storage.is_ssd {
            score += 5;
        }

        // Network: 1 point per 10 Mbps
        score += (self.network.download_mbps as u64) / 10;

        // Cap at 200
        score.min(200).max(1)
    }

    /// Serialize for on-chain storage (compact format)
    pub fn to_chain_format(&self) -> ChainHardwareProfile {
        ChainHardwareProfile {
            cpu_cores: self.cpu.cores,
            cpu_threads: self.cpu.threads,
            ram_gb: self.memory.total_gb,
            gpu_vram_gb: self.gpu.as_ref().map(|g| g.vram_gb).unwrap_or(0),
            gpu_compute_units: self.gpu.as_ref().map(|g| g.compute_units).unwrap_or(0),
            storage_gb: self.storage.total_gb,
            bandwidth_mbps: self.network.download_mbps as u16,
            fingerprint: self.fingerprint,
        }
    }
}

/// Compact format for on-chain storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHardwareProfile {
    pub cpu_cores: u8,
    pub cpu_threads: u8,
    pub ram_gb: u16,
    pub gpu_vram_gb: u16,
    pub gpu_compute_units: u16,
    pub storage_gb: u32,
    pub bandwidth_mbps: u16,
    pub fingerprint: [u8; 32],
}

// ============================================================================
// DETECTION FUNCTIONS
// ============================================================================

#[cfg(target_os = "linux")]
fn detect_cpu() -> anyhow::Result<CpuInfo> {
    use std::fs;

    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;

    let mut vendor = String::new();
    let mut model = String::new();
    let mut cores = 0u8;
    let mut threads = 0u8;
    let mut freq = 0u32;
    let mut cache = 0u32;
    let mut features = Vec::new();

    for line in cpuinfo.lines() {
        if line.starts_with("vendor_id") {
            vendor = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.starts_with("model name") {
            model = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.starts_with("cpu cores") {
            cores = line.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
        } else if line.starts_with("siblings") {
            threads = line.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
        } else if line.starts_with("cpu MHz") {
            freq = line.split(':').nth(1).unwrap_or("0").trim().parse::<f32>().unwrap_or(0.0) as u32;
        } else if line.starts_with("cache size") {
            let size_str = line.split(':').nth(1).unwrap_or("0").trim();
            cache = size_str.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
        } else if line.starts_with("flags") {
            features = line.split(':')
                .nth(1)
                .unwrap_or("")
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }
    }

    // Get max frequency
    let max_freq = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|khz| khz / 1000)
        .unwrap_or(freq);

    Ok(CpuInfo {
        vendor,
        model,
        cores,
        threads,
        base_freq_mhz: freq,
        max_freq_mhz: max_freq,
        cache_kb: cache,
        features,
    })
}

#[cfg(target_os = "linux")]
fn detect_memory() -> anyhow::Result<MemoryInfo> {
    use std::fs;

    let meminfo = fs::read_to_string("/proc/meminfo")?;

    let mut total_kb = 0u64;
    let mut available_kb = 0u64;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        } else if line.starts_with("MemAvailable:") {
            available_kb = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        }
    }

    // Try to get memory speed from dmidecode (requires root)
    let speed = Command::new("dmidecode")
        .args(["-t", "memory"])
        .output()
        .ok()
        .and_then(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Speed:") && line.contains("MT/s") {
                    return line.split_whitespace()
                        .find(|s| s.parse::<u16>().is_ok())
                        .and_then(|s| s.parse().ok());
                }
            }
            None
        })
        .unwrap_or(2400); // Default DDR4 speed

    Ok(MemoryInfo {
        total_gb: (total_kb / 1024 / 1024) as u16,
        available_gb: (available_kb / 1024 / 1024) as u16,
        speed_mhz: speed,
        channels: 2, // Assume dual channel
    })
}

#[cfg(target_os = "linux")]
fn detect_gpu() -> Option<GpuInfo> {
    // Try NVIDIA first
    if let Some(nvidia) = detect_nvidia_gpu() {
        return Some(nvidia);
    }

    // Try AMD
    if let Some(amd) = detect_amd_gpu() {
        return Some(amd);
    }

    // Try Intel
    if let Some(intel) = detect_intel_gpu() {
        return Some(intel);
    }

    None
}

fn detect_nvidia_gpu() -> Option<GpuInfo> {
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.trim().split(',').map(|s| s.trim()).collect();

    if parts.len() >= 3 {
        let vram_mb: u16 = parts[1].parse().unwrap_or(0);

        // Get CUDA version
        let cuda_version = Command::new("nvcc")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines()
                    .find(|l| l.contains("release"))
                    .and_then(|l| l.split("release").nth(1))
                    .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
            });

        // Estimate CUDA cores from model name
        let compute_units = estimate_cuda_cores(parts[0]);

        return Some(GpuInfo {
            vendor: "NVIDIA".to_string(),
            model: parts[0].to_string(),
            vram_gb: vram_mb / 1024,
            compute_units,
            driver_version: parts[2].to_string(),
            cuda_version,
            rocm_version: None,
        });
    }

    None
}

fn detect_amd_gpu() -> Option<GpuInfo> {
    // Check for ROCm
    let output = Command::new("rocm-smi")
        .args(["--showproductname", "--showmeminfo", "vram"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse ROCm output (simplified)
    let stdout = String::from_utf8_lossy(&output.stdout);

    // This is simplified - real implementation would parse properly
    Some(GpuInfo {
        vendor: "AMD".to_string(),
        model: "Unknown AMD GPU".to_string(),
        vram_gb: 8, // Default
        compute_units: 60, // Default
        driver_version: "unknown".to_string(),
        cuda_version: None,
        rocm_version: Some("5.0".to_string()),
    })
}

fn detect_intel_gpu() -> Option<GpuInfo> {
    use std::fs;

    // Check for Intel integrated or Arc GPU
    let drm_path = "/sys/class/drm/card0/device/vendor";
    if let Ok(vendor) = fs::read_to_string(drm_path) {
        if vendor.trim() == "0x8086" {
            // Intel vendor ID
            return Some(GpuInfo {
                vendor: "Intel".to_string(),
                model: "Intel Integrated Graphics".to_string(),
                vram_gb: 0, // Shared memory
                compute_units: 24, // Typical for Intel
                driver_version: "unknown".to_string(),
                cuda_version: None,
                rocm_version: None,
            });
        }
    }

    None
}

fn estimate_cuda_cores(model: &str) -> u16 {
    // Rough estimates based on GPU model
    let model_lower = model.to_lowercase();

    if model_lower.contains("4090") { return 163; }
    if model_lower.contains("4080") { return 97; }
    if model_lower.contains("4070") { return 58; }
    if model_lower.contains("3090") { return 104; }
    if model_lower.contains("3080") { return 87; }
    if model_lower.contains("3070") { return 58; }
    if model_lower.contains("3060") { return 35; }
    if model_lower.contains("2080") { return 29; }
    if model_lower.contains("2070") { return 23; }
    if model_lower.contains("2060") { return 19; }

    // Default
    30
}

#[cfg(target_os = "linux")]
fn detect_storage() -> anyhow::Result<StorageInfo> {
    use std::fs;

    // Get total and available from statvfs
    let stat = nix::sys::statvfs::statvfs("/")?;

    let total_bytes = stat.blocks() * stat.block_size() as u64;
    let available_bytes = stat.blocks_available() * stat.block_size() as u64;

    // Check if SSD
    let is_ssd = fs::read_to_string("/sys/block/sda/queue/rotational")
        .map(|s| s.trim() == "0")
        .unwrap_or(false);

    // Estimate speeds (would need actual benchmark for accuracy)
    let (read_speed, write_speed) = if is_ssd {
        (500, 450) // Typical SATA SSD
    } else {
        (150, 130) // Typical HDD
    };

    Ok(StorageInfo {
        total_gb: (total_bytes / 1024 / 1024 / 1024) as u32,
        available_gb: (available_bytes / 1024 / 1024 / 1024) as u32,
        is_ssd,
        read_speed_mbps: read_speed,
        write_speed_mbps: write_speed,
    })
}

#[cfg(target_os = "linux")]
fn detect_network() -> anyhow::Result<NetworkInfo> {
    // Run speed test (simplified - real implementation would use iperf or similar)
    // For now, return conservative defaults

    Ok(NetworkInfo {
        download_mbps: 100, // Will be validated during contribution
        upload_mbps: 50,
        latency_ms: 20,
    })
}

// ============================================================================
// FINGERPRINTING
// ============================================================================

fn create_fingerprint(
    cpu: &CpuInfo,
    memory: &MemoryInfo,
    gpu: &Option<GpuInfo>,
    storage: &StorageInfo,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // CPU identity
    hasher.update(cpu.vendor.as_bytes());
    hasher.update(cpu.model.as_bytes());
    hasher.update(cpu.cores.to_le_bytes());
    hasher.update(cpu.threads.to_le_bytes());

    // Memory identity
    hasher.update(memory.total_gb.to_le_bytes());
    hasher.update(memory.speed_mhz.to_le_bytes());

    // GPU identity
    if let Some(gpu) = gpu {
        hasher.update(gpu.vendor.as_bytes());
        hasher.update(gpu.model.as_bytes());
        hasher.update(gpu.vram_gb.to_le_bytes());
    }

    // Storage identity
    hasher.update(storage.total_gb.to_le_bytes());

    // Additional entropy from machine-specific sources
    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        }
    }

    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}

// ============================================================================
// CROSS-PLATFORM DETECTION (macOS, Windows, other Unix)
// ============================================================================

#[cfg(not(target_os = "linux"))]
fn detect_cpu() -> anyhow::Result<CpuInfo> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let cpus = sys.cpus();
    let cpu_count = cpus.len() as u8;

    // Get CPU info from first CPU (representative)
    let (vendor, model, freq) = if let Some(cpu) = cpus.first() {
        (
            cpu.vendor_id().to_string(),
            cpu.brand().to_string(),
            cpu.frequency() as u32,
        )
    } else {
        ("Unknown".to_string(), "Unknown CPU".to_string(), 2000)
    };

    // Physical cores = total / 2 (estimate for hyperthreading)
    let physical_cores = (cpu_count / 2).max(1);

    Ok(CpuInfo {
        vendor,
        model,
        cores: physical_cores,
        threads: cpu_count,
        base_freq_mhz: freq,
        max_freq_mhz: freq,
        cache_kb: 8192, // Not easily available cross-platform
        features: vec![], // Platform-specific
    })
}

#[cfg(not(target_os = "linux"))]
fn detect_memory() -> anyhow::Result<MemoryInfo> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_memory();

    let total_bytes = sys.total_memory();
    let available_bytes = sys.available_memory();

    Ok(MemoryInfo {
        total_gb: (total_bytes / 1024 / 1024 / 1024) as u16,
        available_gb: (available_bytes / 1024 / 1024 / 1024) as u16,
        speed_mhz: 2400, // Not easily available cross-platform
        channels: 2,
    })
}

#[cfg(not(target_os = "linux"))]
fn detect_gpu() -> Option<GpuInfo> {
    // GPU detection on macOS/Windows would require platform-specific APIs
    // Metal for macOS, DirectX/DXGI for Windows
    // For now, return None (can be enhanced with wgpu or similar)

    #[cfg(target_os = "macos")]
    {
        // On macOS, check for Apple Silicon GPU or discrete GPU
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Apple") {
                return Some(GpuInfo {
                    vendor: "Apple".to_string(),
                    model: "Apple Silicon GPU".to_string(),
                    vram_gb: 0, // Unified memory
                    compute_units: 10,
                    driver_version: "Metal".to_string(),
                    cuda_version: None,
                    rocm_version: None,
                });
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, try wmic for GPU info
        if let Ok(output) = Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "name,adapterram"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                if !line.trim().is_empty() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        let model = parts.join(" ");
                        let vendor = if model.to_lowercase().contains("nvidia") {
                            "NVIDIA"
                        } else if model.to_lowercase().contains("amd") || model.to_lowercase().contains("radeon") {
                            "AMD"
                        } else if model.to_lowercase().contains("intel") {
                            "Intel"
                        } else {
                            "Unknown"
                        };

                        return Some(GpuInfo {
                            vendor: vendor.to_string(),
                            model,
                            vram_gb: 4, // Would need DirectX query for accurate value
                            compute_units: 20,
                            driver_version: "unknown".to_string(),
                            cuda_version: None,
                            rocm_version: None,
                        });
                    }
                }
            }
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
fn detect_storage() -> anyhow::Result<StorageInfo> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();

    let mut total_bytes: u64 = 0;
    let mut available_bytes: u64 = 0;
    let mut is_ssd = true; // Assume SSD on modern systems

    for disk in disks.list() {
        total_bytes += disk.total_space();
        available_bytes += disk.available_space();

        // Check disk kind if available
        match disk.kind() {
            sysinfo::DiskKind::HDD => is_ssd = false,
            sysinfo::DiskKind::SSD => {}
            _ => {}
        }
    }

    // Estimate speeds based on SSD status
    let (read_speed, write_speed) = if is_ssd {
        (500, 450) // Typical SATA SSD
    } else {
        (150, 130) // Typical HDD
    };

    Ok(StorageInfo {
        total_gb: (total_bytes / 1024 / 1024 / 1024) as u32,
        available_gb: (available_bytes / 1024 / 1024 / 1024) as u32,
        is_ssd,
        read_speed_mbps: read_speed,
        write_speed_mbps: write_speed,
    })
}

#[cfg(not(target_os = "linux"))]
fn detect_network() -> anyhow::Result<NetworkInfo> {
    // Network speed detection requires actual speed tests or interface queries
    // Return conservative defaults
    Ok(NetworkInfo {
        download_mbps: 100,
        upload_mbps: 50,
        latency_ms: 20,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_detection() {
        let profile = HardwareProfile::detect().unwrap();
        println!("CPU: {} cores, {} threads", profile.cpu.cores, profile.cpu.threads);
        println!("RAM: {} GB", profile.memory.total_gb);
        println!("GPU: {:?}", profile.gpu.as_ref().map(|g| &g.model));
        println!("Storage: {} GB", profile.storage.total_gb);
        println!("Score: {}", profile.calculate_score());
    }

    #[test]
    fn test_fingerprint_consistency() {
        let profile1 = HardwareProfile::detect().unwrap();
        let profile2 = HardwareProfile::detect().unwrap();

        assert_eq!(profile1.fingerprint, profile2.fingerprint);
    }
}
