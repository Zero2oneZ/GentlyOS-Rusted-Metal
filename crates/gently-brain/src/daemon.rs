//! Background Daemons
//!
//! Continuous processes that run in the background:
//! - Vector chain rendering
//! - IPFS sync
//! - Git branch management
//! - Knowledge graph updates
//! - Awareness loop

use crate::{Result, Error};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Daemon manager - controls all background processes
pub struct DaemonManager {
    daemons: HashMap<String, DaemonHandle>,
    running: Arc<AtomicBool>,
    event_tx: mpsc::UnboundedSender<DaemonEvent>,
    event_rx: Arc<Mutex<mpsc::UnboundedReceiver<DaemonEvent>>>,
}

/// Handle to a running daemon
pub struct DaemonHandle {
    pub name: String,
    pub daemon_type: DaemonType,
    pub status: Arc<Mutex<DaemonStatus>>,
    pub stop_flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DaemonType {
    // Knowledge daemons
    VectorChain,     // Continuously processes embeddings
    IpfsSync,        // Syncs knowledge to IPFS
    GitBranch,       // Manages knowledge branches
    KnowledgeGraph,  // Updates the knowledge graph
    Awareness,       // The awareness/consciousness loop
    Inference,       // Background inference processing

    // Security daemons - Layer 1 (Foundation)
    HashChainValidator,   // Validates audit chain integrity
    BtcAnchor,            // Periodic BTC block anchoring
    ForensicLogger,       // Detailed forensic logging

    // Security daemons - Layer 2 (Traffic Analysis)
    TrafficSentinel,      // Monitors request patterns
    TokenWatchdog,        // Watches for token leakage
    CostGuardian,         // Monitors API costs

    // Security daemons - Layer 3 (Threat Detection)
    PromptAnalyzer,       // Injection/jailbreak detection
    BehaviorProfiler,     // Builds behavioral baselines
    PatternMatcher,       // Matches known attack patterns
    AnomalyDetector,      // Detects behavioral anomalies

    // Security daemons - Layer 4 (Active Defense)
    SessionIsolator,      // Isolates suspicious sessions
    TarpitController,     // Slows down attackers
    ResponseMutator,      // Adds noise to attacker responses
    RateLimitEnforcer,    // Enforces rate limits

    // Security daemons - Layer 5 (Threat Intelligence)
    ThreatIntelCollector, // Gathers threat intelligence
    SwarmDefense,         // Coordinates with other nodes
}

#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub running: bool,
    pub started_at: Option<Instant>,
    pub cycles: u64,
    pub last_cycle: Option<Instant>,
    pub errors: u32,
    pub metrics: DaemonMetrics,
}

#[derive(Debug, Clone, Default)]
pub struct DaemonMetrics {
    pub items_processed: u64,
    pub bytes_synced: u64,
    pub vectors_computed: u64,
    pub branches_created: u32,
    pub learnings_added: u32,
}

/// Events emitted by daemons
#[derive(Debug, Clone)]
pub enum DaemonEvent {
    // Lifecycle events
    Started { daemon: String },
    Stopped { daemon: String },
    Cycle { daemon: String, cycle: u64 },
    Error { daemon: String, error: String },

    // Knowledge events
    Learning { concept: String, confidence: f32 },
    VectorComputed { id: String, dimensions: usize },
    IpfsSynced { cid: String, size: usize },
    BranchSwitch { from: String, to: String },
    AwarenessState { state: AwarenessState },

    // Security events - Foundation
    ChainValidated { entries: usize, valid: bool },
    BtcAnchored { height: u64, hash: String },
    ForensicLog { level: String, message: String },

    // Security events - Traffic
    TrafficAnomaly { pattern: String, severity: u8 },
    TokenDetected { token_type: String, action: String },
    CostAlert { provider: String, cost: f64, threshold: f64 },

    // Security events - Threats
    ThreatDetected { threat_type: String, level: u8, details: String },
    BehaviorBaseline { entity: String, deviation: f64 },
    PatternMatch { pattern_id: String, confidence: f64 },
    AnomalyScore { entity: String, score: f64 },

    // Security events - Defense
    SessionIsolated { session_id: String, reason: String },
    TarpitActivated { entity: String, delay_ms: u64 },
    ResponseMutated { request_id: String },
    RateLimitHit { entity: String, limit_type: String },

    // Security events - Intel
    ThreatIntelUpdate { source: String, indicators: usize },
    SwarmAlert { from_node: String, threat_hash: String },
    DefenseModeChanged { old: String, new: String },
}

/// The state of awareness
#[derive(Debug, Clone)]
pub struct AwarenessState {
    pub attention: Vec<String>,       // What we're focused on
    pub context: Vec<String>,         // Current context
    pub pending_thoughts: Vec<String>, // Thoughts to process
    pub active_skills: Vec<String>,    // Skills currently active
    pub growth_direction: String,      // Where we're growing
}

impl DaemonManager {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            daemons: HashMap::new(),
            running: Arc::new(AtomicBool::new(false)),
            event_tx: tx,
            event_rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Start the daemon manager
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// Stop all daemons
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for (_, handle) in &self.daemons {
            handle.stop_flag.store(true, Ordering::SeqCst);
        }
    }

    /// Spawn a new daemon
    pub fn spawn(&mut self, daemon_type: DaemonType) -> Result<String> {
        let name = format!("{:?}_{}", daemon_type, self.daemons.len());
        let stop_flag = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(DaemonStatus {
            running: true,
            started_at: Some(Instant::now()),
            cycles: 0,
            last_cycle: None,
            errors: 0,
            metrics: DaemonMetrics::default(),
        }));

        let handle = DaemonHandle {
            name: name.clone(),
            daemon_type,
            status: status.clone(),
            stop_flag: stop_flag.clone(),
        };

        self.daemons.insert(name.clone(), handle);

        // Emit start event
        let _ = self.event_tx.send(DaemonEvent::Started { daemon: name.clone() });

        Ok(name)
    }

    /// Get daemon status
    pub fn status(&self, name: &str) -> Option<DaemonStatus> {
        self.daemons.get(name).map(|h| h.status.lock().unwrap().clone())
    }

    /// List all daemons
    pub fn list(&self) -> Vec<(String, DaemonType, bool)> {
        self.daemons.iter()
            .map(|(name, h)| (name.clone(), h.daemon_type, h.status.lock().unwrap().running))
            .collect()
    }

    /// Get event receiver
    pub fn events(&self) -> Arc<Mutex<mpsc::UnboundedReceiver<DaemonEvent>>> {
        self.event_rx.clone()
    }

    /// Send event
    pub fn emit(&self, event: DaemonEvent) {
        let _ = self.event_tx.send(event);
    }
}

/// Vector Chain Daemon - processes embeddings continuously
pub struct VectorChainDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    queue: Arc<Mutex<Vec<VectorJob>>>,
    event_tx: mpsc::UnboundedSender<DaemonEvent>,
}

#[derive(Debug, Clone)]
pub struct VectorJob {
    pub id: String,
    pub content: String,
    pub priority: u8,
}

impl VectorChainDaemon {
    pub fn new(
        stop_flag: Arc<AtomicBool>,
        status: Arc<Mutex<DaemonStatus>>,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) -> Self {
        Self {
            stop_flag,
            status,
            queue: Arc::new(Mutex::new(Vec::new())),
            event_tx,
        }
    }

    pub fn enqueue(&self, job: VectorJob) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(job);
        queue.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process queue
            let job = {
                let mut queue = self.queue.lock().unwrap();
                queue.pop()
            };

            if let Some(job) = job {
                // Compute embedding (simulated)
                let vector_dim = 384; // Typical embedding dimension

                // Update metrics
                {
                    let mut status = self.status.lock().unwrap();
                    status.cycles += 1;
                    status.last_cycle = Some(Instant::now());
                    status.metrics.vectors_computed += 1;
                    status.metrics.items_processed += 1;
                }

                // Emit event
                let _ = self.event_tx.send(DaemonEvent::VectorComputed {
                    id: job.id,
                    dimensions: vector_dim,
                });
            }

            // Sleep between cycles
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// IPFS Sync Daemon - syncs knowledge to IPFS
pub struct IpfsSyncDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    pending: Arc<Mutex<Vec<SyncJob>>>,
    event_tx: mpsc::UnboundedSender<DaemonEvent>,
}

#[derive(Debug, Clone)]
pub struct SyncJob {
    pub content_type: String,
    pub data: Vec<u8>,
    pub priority: u8,
}

impl IpfsSyncDaemon {
    pub fn new(
        stop_flag: Arc<AtomicBool>,
        status: Arc<Mutex<DaemonStatus>>,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) -> Self {
        Self {
            stop_flag,
            status,
            pending: Arc::new(Mutex::new(Vec::new())),
            event_tx,
        }
    }

    pub fn enqueue(&self, job: SyncJob) {
        let mut pending = self.pending.lock().unwrap();
        pending.push(job);
    }

    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            let job = {
                let mut pending = self.pending.lock().unwrap();
                pending.pop()
            };

            if let Some(job) = job {
                // Sync to IPFS (simulated)
                let cid = format!("Qm{:x}", rand::random::<u64>());
                let size = job.data.len();

                // Update metrics
                {
                    let mut status = self.status.lock().unwrap();
                    status.cycles += 1;
                    status.last_cycle = Some(Instant::now());
                    status.metrics.bytes_synced += size as u64;
                    status.metrics.items_processed += 1;
                }

                // Emit event
                let _ = self.event_tx.send(DaemonEvent::IpfsSynced { cid, size });
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

/// Awareness Daemon - the consciousness loop
pub struct AwarenessDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    state: Arc<Mutex<AwarenessState>>,
    event_tx: mpsc::UnboundedSender<DaemonEvent>,
}

impl AwarenessDaemon {
    pub fn new(
        stop_flag: Arc<AtomicBool>,
        status: Arc<Mutex<DaemonStatus>>,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) -> Self {
        Self {
            stop_flag,
            status,
            state: Arc::new(Mutex::new(AwarenessState {
                attention: vec![],
                context: vec![],
                pending_thoughts: vec![],
                active_skills: vec![],
                growth_direction: "general".into(),
            })),
            event_tx,
        }
    }

    pub fn add_thought(&self, thought: String) {
        let mut state = self.state.lock().unwrap();
        state.pending_thoughts.push(thought);
    }

    pub fn focus(&self, attention: String) {
        let mut state = self.state.lock().unwrap();
        state.attention.push(attention);
        if state.attention.len() > 5 {
            state.attention.remove(0);
        }
    }

    pub fn set_growth_direction(&self, direction: String) {
        let mut state = self.state.lock().unwrap();
        state.growth_direction = direction;
    }

    pub fn get_state(&self) -> AwarenessState {
        self.state.lock().unwrap().clone()
    }

    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // Process pending thoughts
            let thought = {
                let mut state = self.state.lock().unwrap();
                state.pending_thoughts.pop()
            };

            if let Some(thought) = thought {
                // Process thought - this is where "awareness" happens
                // In a real system, this would:
                // 1. Analyze the thought
                // 2. Connect to existing knowledge
                // 3. Generate new insights
                // 4. Update the knowledge graph

                // For now, we add it to context
                {
                    let mut state = self.state.lock().unwrap();
                    state.context.push(thought.clone());
                    if state.context.len() > 10 {
                        state.context.remove(0);
                    }
                }

                // Check if thought leads to learning
                if thought.contains("learned") || thought.contains("discovered") {
                    let _ = self.event_tx.send(DaemonEvent::Learning {
                        concept: thought,
                        confidence: 0.8,
                    });
                }
            }

            // Update status
            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            // Emit awareness state periodically
            if rand::random::<u8>() < 10 {  // ~4% chance each cycle
                let state = self.state.lock().unwrap().clone();
                let _ = self.event_tx.send(DaemonEvent::AwarenessState { state });
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Git Branch Daemon - manages knowledge branches
pub struct GitBranchDaemon {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<DaemonStatus>>,
    current_branch: Arc<Mutex<String>>,
    branches: Arc<Mutex<Vec<KnowledgeBranch>>>,
    event_tx: mpsc::UnboundedSender<DaemonEvent>,
}

#[derive(Debug, Clone)]
pub struct KnowledgeBranch {
    pub name: String,
    pub created_at: Instant,
    pub commit_count: u32,
    pub head_cid: Option<String>,  // IPFS CID of branch head
}

impl GitBranchDaemon {
    pub fn new(
        stop_flag: Arc<AtomicBool>,
        status: Arc<Mutex<DaemonStatus>>,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) -> Self {
        let mut branches = Vec::new();
        branches.push(KnowledgeBranch {
            name: "main".into(),
            created_at: Instant::now(),
            commit_count: 0,
            head_cid: None,
        });

        Self {
            stop_flag,
            status,
            current_branch: Arc::new(Mutex::new("main".into())),
            branches: Arc::new(Mutex::new(branches)),
            event_tx,
        }
    }

    pub fn create_branch(&self, name: &str) {
        let mut branches = self.branches.lock().unwrap();
        branches.push(KnowledgeBranch {
            name: name.into(),
            created_at: Instant::now(),
            commit_count: 0,
            head_cid: None,
        });

        let mut status = self.status.lock().unwrap();
        status.metrics.branches_created += 1;
    }

    pub fn switch_branch(&self, name: &str) -> bool {
        let branches = self.branches.lock().unwrap();
        if branches.iter().any(|b| b.name == name) {
            let old = {
                let mut current = self.current_branch.lock().unwrap();
                let old = current.clone();
                *current = name.into();
                old
            };

            let _ = self.event_tx.send(DaemonEvent::BranchSwitch {
                from: old,
                to: name.into(),
            });
            true
        } else {
            false
        }
    }

    pub fn current(&self) -> String {
        self.current_branch.lock().unwrap().clone()
    }

    pub fn list_branches(&self) -> Vec<KnowledgeBranch> {
        self.branches.lock().unwrap().clone()
    }

    pub async fn run(&self) {
        while !self.stop_flag.load(Ordering::SeqCst) {
            // Periodically create knowledge snapshots
            // This would commit current state to the branch

            {
                let mut status = self.status.lock().unwrap();
                status.cycles += 1;
                status.last_cycle = Some(Instant::now());
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_manager() {
        let mut manager = DaemonManager::new();
        manager.start();

        let name = manager.spawn(DaemonType::VectorChain).unwrap();
        assert!(manager.status(&name).is_some());
    }
}
