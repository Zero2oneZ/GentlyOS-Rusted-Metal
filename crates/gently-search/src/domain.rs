//! 72-Domain Semantic Router
//!
//! Routes thoughts and queries to semantic domains for focused search.
//! Inspired by the 72 Names concept but implemented as practical categories.

use serde::{Deserialize, Serialize};

/// A semantic domain for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    /// Domain index (0-71)
    pub index: u8,

    /// Short code (3 chars)
    pub code: String,

    /// Display name
    pub name: String,

    /// Keywords that route to this domain
    pub keywords: Vec<String>,

    /// Description
    pub description: String,
}

impl Domain {
    pub fn new(index: u8, code: &str, name: &str, description: &str) -> Self {
        Self {
            index,
            code: code.to_string(),
            name: name.to_string(),
            keywords: Vec::new(),
            description: description.to_string(),
        }
    }

    pub fn with_keywords(mut self, keywords: &[&str]) -> Self {
        self.keywords = keywords.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Router for 72 semantic domains
pub struct DomainRouter {
    domains: Vec<Domain>,
}

impl Default for DomainRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainRouter {
    /// Create router with default domains
    pub fn new() -> Self {
        Self {
            domains: Self::default_domains(),
        }
    }

    /// Get domain by index
    pub fn get(&self, index: u8) -> Option<&Domain> {
        self.domains.get(index as usize)
    }

    /// Route a query to domains (returns top matches)
    pub fn route(&self, query: &str) -> Vec<(u8, f32)> {
        let query_lower = query.to_lowercase();
        let words: Vec<&str> = query_lower.split_whitespace().collect();

        let mut scores: Vec<(u8, f32)> = self
            .domains
            .iter()
            .map(|d| {
                let mut score = 0.0_f32;

                // Keyword matches
                for kw in &d.keywords {
                    for word in &words {
                        if kw.contains(word) || word.contains(kw) {
                            score += 1.0;
                        }
                    }
                }

                // Name match
                if d.name.to_lowercase().contains(&query_lower) {
                    score += 2.0;
                }

                (d.index, score)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scores.truncate(5);
        scores
    }

    /// Route a query to primary domain
    pub fn route_primary(&self, query: &str) -> Option<u8> {
        self.route(query).first().map(|(idx, _)| *idx)
    }

    /// Default 72 domains (grouped into 7 meta-categories)
    fn default_domains() -> Vec<Domain> {
        let mut domains = Vec::with_capacity(72);

        // Meta-Category 1: Creation (0-10) - Genesis, building, starting
        domains.push(
            Domain::new(0, "GEN", "Genesis", "Origins, beginnings, initialization")
                .with_keywords(&["init", "start", "begin", "create", "new", "genesis"]),
        );
        domains.push(
            Domain::new(1, "BLD", "Building", "Construction, assembly, development")
                .with_keywords(&["build", "make", "construct", "develop", "implement"]),
        );
        domains.push(
            Domain::new(2, "DSN", "Design", "Planning, architecture, structure")
                .with_keywords(&["design", "plan", "architect", "structure", "layout"]),
        );
        domains.push(
            Domain::new(3, "GRW", "Growth", "Expansion, scaling, evolution")
                .with_keywords(&["grow", "scale", "expand", "evolve", "increase"]),
        );
        domains.push(
            Domain::new(4, "INV", "Innovation", "Novelty, creativity, invention")
                .with_keywords(&["innovate", "invent", "creative", "novel", "new"]),
        );
        domains.push(
            Domain::new(5, "PRO", "Projects", "Initiatives, endeavors, undertakings")
                .with_keywords(&["project", "initiative", "effort", "work"]),
        );
        domains.push(
            Domain::new(6, "TSK", "Tasks", "Actions, to-dos, work items")
                .with_keywords(&["task", "todo", "action", "item", "do"]),
        );
        domains.push(
            Domain::new(7, "GOL", "Goals", "Objectives, targets, aims")
                .with_keywords(&["goal", "objective", "target", "aim", "achieve"]),
        );
        domains.push(
            Domain::new(8, "PLN", "Planning", "Strategy, roadmap, scheduling")
                .with_keywords(&["plan", "strategy", "roadmap", "schedule", "timeline"]),
        );
        domains.push(
            Domain::new(9, "IDE", "Ideas", "Concepts, thoughts, possibilities")
                .with_keywords(&["idea", "concept", "thought", "maybe", "possibility"]),
        );
        domains.push(
            Domain::new(10, "EXP", "Experiments", "Tests, trials, explorations")
                .with_keywords(&["experiment", "test", "try", "explore", "trial"]),
        );

        // Meta-Category 2: Protection (11-20) - Security, validation, safety
        domains.push(
            Domain::new(11, "SEC", "Security", "Protection, safety, defense")
                .with_keywords(&["security", "secure", "protect", "safe", "defense"]),
        );
        domains.push(
            Domain::new(12, "CRY", "Cryptography", "Encryption, hashing, keys")
                .with_keywords(&["crypto", "encrypt", "hash", "key", "cipher", "xor"]),
        );
        domains.push(
            Domain::new(13, "AUT", "Authentication", "Identity, login, verification")
                .with_keywords(&["auth", "login", "identity", "verify", "credential"]),
        );
        domains.push(
            Domain::new(14, "VAL", "Validation", "Checking, verification, testing")
                .with_keywords(&["validate", "check", "verify", "test", "assert"]),
        );
        domains.push(
            Domain::new(15, "ERR", "Errors", "Bugs, issues, problems")
                .with_keywords(&["error", "bug", "issue", "problem", "fix", "broken"]),
        );
        domains.push(
            Domain::new(16, "DBG", "Debugging", "Troubleshooting, investigation")
                .with_keywords(&["debug", "trace", "investigate", "diagnose"]),
        );
        domains.push(
            Domain::new(17, "PRM", "Permissions", "Access control, authorization")
                .with_keywords(&["permission", "access", "authorize", "allow", "deny"]),
        );
        domains.push(
            Domain::new(18, "BCK", "Backup", "Recovery, restore, redundancy")
                .with_keywords(&["backup", "restore", "recover", "redundant"]),
        );
        domains.push(
            Domain::new(19, "AUD", "Audit", "Logging, tracking, compliance")
                .with_keywords(&["audit", "log", "track", "compliance", "monitor"]),
        );
        domains.push(
            Domain::new(20, "RVW", "Review", "Code review, inspection, analysis")
                .with_keywords(&["review", "inspect", "analyze", "critique"]),
        );

        // Meta-Category 3: Manifestation (21-30) - Execution, deployment, delivery
        domains.push(
            Domain::new(21, "DEP", "Deployment", "Release, shipping, launch")
                .with_keywords(&["deploy", "release", "ship", "launch", "publish"]),
        );
        domains.push(
            Domain::new(22, "EXE", "Execution", "Running, processing, performing")
                .with_keywords(&["execute", "run", "process", "perform"]),
        );
        domains.push(
            Domain::new(23, "OPS", "Operations", "DevOps, maintenance, infrastructure")
                .with_keywords(&["ops", "devops", "infra", "maintain", "operate"]),
        );
        domains.push(
            Domain::new(24, "MON", "Monitoring", "Observability, metrics, alerts")
                .with_keywords(&["monitor", "observe", "metric", "alert", "dashboard"]),
        );
        domains.push(
            Domain::new(25, "SRV", "Services", "APIs, endpoints, microservices")
                .with_keywords(&["service", "api", "endpoint", "microservice"]),
        );
        domains.push(
            Domain::new(26, "CLU", "Cloud", "AWS, GCP, Azure, infrastructure")
                .with_keywords(&["cloud", "aws", "gcp", "azure", "serverless"]),
        );
        domains.push(
            Domain::new(27, "CON", "Containers", "Docker, Kubernetes, orchestration")
                .with_keywords(&["container", "docker", "kubernetes", "k8s", "pod"]),
        );
        domains.push(
            Domain::new(28, "NET", "Networking", "HTTP, TCP, protocols, connectivity")
                .with_keywords(&["network", "http", "tcp", "protocol", "socket"]),
        );
        domains.push(
            Domain::new(29, "PER", "Performance", "Speed, optimization, efficiency")
                .with_keywords(&["performance", "fast", "optimize", "efficient", "speed"]),
        );
        domains.push(
            Domain::new(30, "SCA", "Scaling", "Load balancing, distribution")
                .with_keywords(&["scale", "load", "balance", "distribute", "shard"]),
        );

        // Meta-Category 4: Knowledge (31-40) - Learning, documentation, data
        domains.push(
            Domain::new(31, "DOC", "Documentation", "Docs, guides, README")
                .with_keywords(&["doc", "documentation", "readme", "guide", "manual"]),
        );
        domains.push(
            Domain::new(32, "LRN", "Learning", "Tutorials, courses, education")
                .with_keywords(&["learn", "tutorial", "course", "study", "education"]),
        );
        domains.push(
            Domain::new(33, "REF", "Reference", "APIs, specs, standards")
                .with_keywords(&["reference", "spec", "standard", "api"]),
        );
        domains.push(
            Domain::new(34, "DAT", "Data", "Storage, databases, persistence")
                .with_keywords(&["data", "database", "storage", "persist", "store"]),
        );
        domains.push(
            Domain::new(35, "MOD", "Models", "Schemas, types, structures")
                .with_keywords(&["model", "schema", "type", "struct", "entity"]),
        );
        domains.push(
            Domain::new(36, "SRC", "Search", "Query, find, lookup")
                .with_keywords(&["search", "query", "find", "lookup", "index"]),
        );
        domains.push(
            Domain::new(37, "VEC", "Vectors", "Embeddings, ML, semantic")
                .with_keywords(&["vector", "embedding", "semantic", "similarity"]),
        );
        domains.push(
            Domain::new(38, "ANL", "Analytics", "Statistics, metrics, insights")
                .with_keywords(&["analytics", "statistic", "insight", "report"]),
        );
        domains.push(
            Domain::new(39, "VIS", "Visualization", "Charts, graphs, UI")
                .with_keywords(&["visualize", "chart", "graph", "ui", "display"]),
        );
        domains.push(
            Domain::new(40, "INT", "Integration", "Connectors, adapters, bridges")
                .with_keywords(&["integrate", "connect", "adapter", "bridge", "sync"]),
        );

        // Meta-Category 5: Memory (41-50) - State, context, persistence
        domains.push(
            Domain::new(41, "STE", "State", "Variables, memory, context")
                .with_keywords(&["state", "variable", "memory", "context"]),
        );
        domains.push(
            Domain::new(42, "CAC", "Cache", "Caching, memoization, speed")
                .with_keywords(&["cache", "memoize", "store", "remember"]),
        );
        domains.push(
            Domain::new(43, "SES", "Sessions", "User sessions, cookies, tokens")
                .with_keywords(&["session", "cookie", "token", "jwt"]),
        );
        domains.push(
            Domain::new(44, "HIS", "History", "Logs, timeline, versioning")
                .with_keywords(&["history", "log", "timeline", "version", "changelog"]),
        );
        domains.push(
            Domain::new(45, "CTX", "Context", "Environment, config, settings")
                .with_keywords(&["context", "environment", "config", "setting"]),
        );
        domains.push(
            Domain::new(46, "FED", "Feed", "Living feed, activity, stream")
                .with_keywords(&["feed", "activity", "stream", "timeline"]),
        );
        domains.push(
            Domain::new(47, "NTF", "Notifications", "Alerts, events, webhooks")
                .with_keywords(&["notification", "alert", "event", "webhook"]),
        );
        domains.push(
            Domain::new(48, "QUE", "Queues", "Jobs, workers, async")
                .with_keywords(&["queue", "job", "worker", "async", "background"]),
        );
        domains.push(
            Domain::new(49, "PUB", "PubSub", "Messaging, events, broadcasts")
                .with_keywords(&["pubsub", "message", "broadcast", "subscribe"]),
        );
        domains.push(
            Domain::new(50, "SYN", "Sync", "Replication, consistency")
                .with_keywords(&["sync", "replicate", "consistent", "merge"]),
        );

        // Meta-Category 6: Cycles (51-60) - Iteration, automation, flow
        domains.push(
            Domain::new(51, "LOP", "Loops", "Iteration, recursion, cycles")
                .with_keywords(&["loop", "iterate", "recurse", "cycle", "repeat"]),
        );
        domains.push(
            Domain::new(52, "AUT", "Automation", "Scripts, pipelines, CI/CD")
                .with_keywords(&["automate", "script", "pipeline", "ci", "cd"]),
        );
        domains.push(
            Domain::new(53, "WRK", "Workflows", "Processes, procedures, flows")
                .with_keywords(&["workflow", "process", "procedure", "flow"]),
        );
        domains.push(
            Domain::new(54, "EVT", "Events", "Triggers, handlers, reactions")
                .with_keywords(&["event", "trigger", "handler", "react", "hook"]),
        );
        domains.push(
            Domain::new(55, "SCH", "Scheduling", "Cron, timers, periodic")
                .with_keywords(&["schedule", "cron", "timer", "periodic", "interval"]),
        );
        domains.push(
            Domain::new(56, "RTY", "Retry", "Resilience, backoff, recovery")
                .with_keywords(&["retry", "resilient", "backoff", "recover"]),
        );
        domains.push(
            Domain::new(57, "TRN", "Transactions", "ACID, atomicity, consistency")
                .with_keywords(&["transaction", "atomic", "commit", "rollback"]),
        );
        domains.push(
            Domain::new(58, "MIG", "Migrations", "Schema changes, upgrades")
                .with_keywords(&["migration", "migrate", "upgrade", "schema"]),
        );
        domains.push(
            Domain::new(59, "TST", "Testing", "Unit, integration, e2e")
                .with_keywords(&["test", "unit", "integration", "e2e", "spec"]),
        );
        domains.push(
            Domain::new(60, "BEN", "Benchmarks", "Performance testing, load")
                .with_keywords(&["benchmark", "perf", "load", "stress"]),
        );

        // Meta-Category 7: Completion (61-71) - Finalization, communication, delivery
        domains.push(
            Domain::new(61, "FIN", "Finalization", "Completion, closure, done")
                .with_keywords(&["final", "complete", "done", "finish", "close"]),
        );
        domains.push(
            Domain::new(62, "CMT", "Communication", "Chat, messaging, collaboration")
                .with_keywords(&["chat", "message", "collaborate", "communicate"]),
        );
        domains.push(
            Domain::new(63, "RPT", "Reporting", "Status, progress, summaries")
                .with_keywords(&["report", "status", "progress", "summary"]),
        );
        domains.push(
            Domain::new(64, "PRZ", "Presentation", "Demos, showcases, sharing")
                .with_keywords(&["present", "demo", "showcase", "share"]),
        );
        domains.push(
            Domain::new(65, "FDB", "Feedback", "Reviews, comments, input")
                .with_keywords(&["feedback", "review", "comment", "input"]),
        );
        domains.push(
            Domain::new(66, "HLP", "Help", "Support, assistance, guidance")
                .with_keywords(&["help", "support", "assist", "guide"]),
        );
        domains.push(
            Domain::new(67, "USR", "Users", "Accounts, profiles, people")
                .with_keywords(&["user", "account", "profile", "person"]),
        );
        domains.push(
            Domain::new(68, "TEM", "Team", "Collaboration, organization")
                .with_keywords(&["team", "org", "collaborate", "member"]),
        );
        domains.push(
            Domain::new(69, "BLK", "Blockchain", "Crypto, tokens, web3")
                .with_keywords(&["blockchain", "crypto", "token", "web3", "solana", "btc"]),
        );
        domains.push(
            Domain::new(70, "AI", "AI/ML", "Machine learning, agents, LLMs")
                .with_keywords(&["ai", "ml", "llm", "agent", "model", "gpt", "claude"]),
        );
        domains.push(
            Domain::new(71, "GEN", "GentlyOS", "GentlyOS-specific domain")
                .with_keywords(&["gently", "gentlyos", "dance", "xor", "feed"]),
        );

        domains
    }

    /// Get all domains
    pub fn all(&self) -> &[Domain] {
        &self.domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_routing() {
        let router = DomainRouter::new();

        let routes = router.route("How do I fix this security bug?");
        assert!(!routes.is_empty());

        // Should match security and/or errors domain
        let indices: Vec<_> = routes.iter().map(|(i, _)| *i).collect();
        assert!(indices.contains(&11) || indices.contains(&15)); // SEC or ERR
    }

    #[test]
    fn test_gentlyos_domain() {
        let router = DomainRouter::new();

        let routes = router.route("GentlyOS dance protocol XOR");

        // Should match GentlyOS domain (71)
        assert!(routes.iter().any(|(i, _)| *i == 71));
    }
}
