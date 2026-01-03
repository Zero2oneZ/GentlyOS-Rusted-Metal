//! GentlyOS Guardian Node CLI
//!
//! Free tier participation in the GentlyOS network.
//! Contribute compute, earn GNTLY tokens.

use gently_guardian::{Guardian, GuardianConfig, NodeTier};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("gently_guardian=info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match command {
        "start" => start_guardian().await,
        "register" => register_node().await,
        "benchmark" => run_benchmark().await,
        "status" => show_status().await,
        "claim" => claim_rewards().await,
        "upgrade" => upgrade_tier(&args).await,
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!(
        r#"
GentlyOS Guardian Node v0.1.0

USAGE:
    gently-guardian <COMMAND>

COMMANDS:
    start       Start the guardian node (runs continuously)
    register    Register node on-chain
    benchmark   Run hardware benchmark
    status      Show current stats
    claim       Claim pending rewards
    upgrade     Upgrade node tier (requires stake)
    help        Show this help message

ENVIRONMENT:
    GENTLY_RPC       Solana RPC endpoint (default: mainnet)
    GENTLY_WALLET    Path to wallet keypair
    GENTLY_CPU       Max CPU usage % (default: 50)
    GENTLY_GPU       Max GPU usage % (default: 80)
    GENTLY_STORAGE   Max storage GB (default: 10)
    GENTLY_IDLE      Only run when idle (default: true)
    GENTLY_POWER     Only run on AC power (default: true)

EXAMPLES:
    # Start guardian node
    gently-guardian start

    # Check earnings
    gently-guardian status

    # Claim rewards
    gently-guardian claim

    # Upgrade to Home tier
    gently-guardian upgrade home
"#
    );
}

async fn start_guardian() -> anyhow::Result<()> {
    println!("Starting GentlyOS Guardian Node...\n");

    let config = load_config();
    let mut guardian = Guardian::new(config).await?;

    // Register if not already
    println!("Registering node...");
    let tx = guardian.register().await?;
    println!("Registered: {}\n", tx);

    // Start contribution loop
    guardian.start().await
}

async fn register_node() -> anyhow::Result<()> {
    println!("Registering GentlyOS Guardian Node...\n");

    let config = load_config();
    let guardian = Guardian::new(config).await?;

    let tx = guardian.register().await?;
    println!("Node registered successfully!");
    println!("Transaction: {}", tx);

    Ok(())
}

async fn run_benchmark() -> anyhow::Result<()> {
    use gently_guardian::{hardware::HardwareProfile, benchmark::Benchmark};

    println!("Running hardware benchmark...\n");

    let hardware = HardwareProfile::detect()?;
    println!("Hardware detected:");
    println!("  CPU: {} ({} cores)", hardware.cpu.model, hardware.cpu.cores);
    println!("  RAM: {} GB", hardware.memory.total_gb);
    if let Some(gpu) = &hardware.gpu {
        println!("  GPU: {} ({} GB)", gpu.model, gpu.vram_gb);
    }
    println!();

    let benchmark = Benchmark::run_full(&hardware).await?;

    println!("Benchmark Results:");
    println!("  CPU Hash Rate: {} H/s", benchmark.cpu.hash_rate);
    println!("  CPU FLOPS: {}", benchmark.cpu.flops);
    println!("  Memory Read: {} MB/s", benchmark.memory.read_bandwidth);
    println!("  Memory Write: {} MB/s", benchmark.memory.write_bandwidth);
    println!("  Storage Read: {} MB/s", benchmark.storage.seq_read);
    println!("  Storage Write: {} MB/s", benchmark.storage.seq_write);

    if let Some(gpu) = &benchmark.gpu {
        println!("  GPU Inference: {} ms", gpu.inference_time_ms);
        println!("  GPU TFLOPS: {:.2}", gpu.tflops);
    }

    println!("\nHardware Score: {}", hardware.calculate_score());

    // Validate
    let validation = gently_guardian::benchmark::validate_benchmark(&hardware, &benchmark);
    if validation.valid {
        println!("\nValidation: PASSED");
    } else {
        println!("\nValidation: FAILED");
        for issue in &validation.issues {
            println!("  - {}", issue);
        }
    }

    Ok(())
}

async fn show_status() -> anyhow::Result<()> {
    let config = load_config();
    let guardian = Guardian::new(config).await?;
    let stats = guardian.stats();

    println!("GentlyOS Guardian Status\n");
    println!("Tier:            {}", stats.tier);
    println!("Hardware Score:  {}", stats.hardware_score);
    println!("Uptime:          {:.2} hours", stats.uptime_hours);
    println!("Quality Score:   {:.2}%", stats.quality_score * 100.0);
    println!("Tasks Completed: {}", stats.tasks_completed);
    println!();
    println!("Pending Rewards: {} GNTLY", stats.pending_rewards as f64 / 1_000_000.0);
    println!("Total Earned:    {} GNTLY", stats.total_earned as f64 / 1_000_000.0);

    Ok(())
}

async fn claim_rewards() -> anyhow::Result<()> {
    let config = load_config();
    let guardian = Guardian::new(config).await?;

    println!("Claiming rewards...\n");
    let claimed = guardian.claim_rewards().await?;

    if claimed > 0 {
        println!("Claimed {} GNTLY!", claimed as f64 / 1_000_000.0);
    } else {
        println!("No pending rewards to claim.");
    }

    Ok(())
}

async fn upgrade_tier(args: &[String]) -> anyhow::Result<()> {
    let tier_name = args.get(2).map(|s| s.as_str()).unwrap_or("home");

    let target = match tier_name.to_lowercase().as_str() {
        "guardian" | "free" => NodeTier::Guardian,
        "home" => NodeTier::Home,
        "business" => NodeTier::Business,
        "studio" => NodeTier::Studio,
        _ => {
            eprintln!("Unknown tier: {}", tier_name);
            eprintln!("Valid tiers: guardian, home, business, studio");
            return Ok(());
        }
    };

    let stake_required = match target {
        NodeTier::Guardian => 0,
        NodeTier::Home => 1000,
        NodeTier::Business => 5000,
        NodeTier::Studio => 25000,
    };

    println!("Upgrading to {} tier...", target);
    if stake_required > 0 {
        println!("Stake required: {} GNTLY\n", stake_required);
    }

    let config = load_config();
    let guardian = Guardian::new(config).await?;
    let tx = guardian.upgrade_tier(target).await?;

    println!("Upgrade successful!");
    println!("Transaction: {}", tx);

    Ok(())
}

fn load_config() -> GuardianConfig {
    let rpc = env::var("GENTLY_RPC")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let wallet = env::var("GENTLY_WALLET")
        .unwrap_or_else(|_| "~/.config/solana/id.json".to_string());
    let cpu_limit = env::var("GENTLY_CPU")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let gpu_limit = env::var("GENTLY_GPU")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let storage_limit = env::var("GENTLY_STORAGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let idle_only = env::var("GENTLY_IDLE")
        .map(|s| s != "false" && s != "0")
        .unwrap_or(true);
    let power_only = env::var("GENTLY_POWER")
        .map(|s| s != "false" && s != "0")
        .unwrap_or(true);

    GuardianConfig {
        share_cpu: true,
        share_gpu: true,
        share_storage: true,
        cpu_limit,
        gpu_limit,
        storage_limit_gb: storage_limit,
        idle_only,
        power_only,
        wallet_path: wallet,
        rpc_endpoint: rpc,
        check_interval: std::time::Duration::from_secs(60),
    }
}
