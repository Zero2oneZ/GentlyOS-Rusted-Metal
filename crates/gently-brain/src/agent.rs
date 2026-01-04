//! Living SVG Agents
//!
//! The SVG IS the agent. Self-contained. Self-executing. Self-improving.
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  agent.svg (hash: 7f3a...)              │
//! ├─────────────────────────────────────────┤
//! │  <svg>                                  │
//! │    <!-- VISUAL: What I am -->           │
//! │    <rect>, <path>, <text>...            │
//! │                                         │
//! │    <!-- BRAIN: What I do -->            │
//! │    <foreignObject>                      │
//! │      <wasm src="data:..." />            │
//! │    </foreignObject>                     │
//! │                                         │
//! │    <!-- MEMORY: What I learned -->      │
//! │    <metadata>                           │
//! │      lora_chain: 8b4c...                │
//! │      parent: 6a2f...                    │
//! │    </metadata>                          │
//! │  </svg>                                 │
//! └─────────────────────────────────────────┘
//!
//! Open in browser → see what it is
//! Run in WASM → it thinks
//! Failure → pattern → LoRA → new SVG hash
//! Fork → your version → your hash
//! ```

use gently_core::{Hash, Kind, Blob, Manifest, BlobStore, TAG_PARENT, TAG_NEXT, TAG_CODE, TAG_WEIGHTS};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Agent-specific tags
pub const TAG_VISUAL: u16 = 0x0600;
pub const TAG_BRAIN: u16 = 0x0601;
pub const TAG_MEMORY: u16 = 0x0602;
pub const TAG_LORA: u16 = 0x0603;
pub const TAG_OBSERVATION: u16 = 0x0604;
pub const TAG_GENERATION: u16 = 0x0605;
pub const TAG_MERGED_FROM: u16 = 0x0606;

/// Agent identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeta {
    pub name: String,
    pub generation: u64,
    pub born: u64,
    pub parent: Option<String>,  // hex hash
    pub traits: Vec<String>,
}

/// Living SVG Agent
pub struct Agent {
    pub hash: Hash,
    pub svg: String,
    pub wasm: Vec<u8>,
    pub lora_chain: Hash,
    pub meta: AgentMeta,
}

/// Agent runtime
pub struct AgentRuntime {
    store: BlobStore,
    agents: HashMap<Hash, Agent>,
    observations: Vec<Observation>,
}

/// One agent observing another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub observer: Hash,
    pub observed: Hash,
    pub input: Vec<f32>,
    pub output: Vec<f32>,
    pub loss: f32,
    pub timestamp: u64,
}

impl AgentRuntime {
    pub fn new() -> Self {
        Self {
            store: BlobStore::new(),
            agents: HashMap::new(),
            observations: Vec::new(),
        }
    }

    /// Spawn new agent from SVG
    pub fn spawn(&mut self, name: &str, wasm: Vec<u8>, lora_chain: Option<Hash>) -> Hash {
        let meta = AgentMeta {
            name: name.to_string(),
            generation: 0,
            born: now(),
            parent: None,
            traits: vec![],
        };

        // Store WASM brain
        let wasm_hash = self.store.put(Blob::new(Kind::Wasm, wasm.clone()));

        // Store or reference LoRA chain
        let lora_hash = lora_chain.unwrap_or_else(|| {
            self.store.put(Blob::new(Kind::Manifest, vec![]))
        });

        // Generate SVG
        let svg = self.generate_svg(&meta, &wasm_hash, &lora_hash);
        let svg_bytes = svg.as_bytes().to_vec();

        // Build agent manifest
        let mut manifest = Manifest::new();
        manifest.add(TAG_BRAIN, wasm_hash);
        manifest.add(TAG_MEMORY, lora_hash);

        // Store SVG visual
        let visual_hash = self.store.put(Blob::new(Kind::Svg, svg_bytes));
        manifest.add(TAG_VISUAL, visual_hash);

        // Store metadata
        let meta_hash = self.store.put(Blob::new(Kind::Json,
            serde_json::to_vec(&meta).unwrap()));
        manifest.add(TAG_GENERATION, meta_hash);

        // Agent = manifest blob
        let agent_blob = manifest.to_blob();
        let agent_hash = self.store.put(agent_blob);

        let agent = Agent {
            hash: agent_hash,
            svg,
            wasm,
            lora_chain: lora_hash,
            meta,
        };

        self.agents.insert(agent_hash, agent);
        agent_hash
    }

    /// Fork agent (your version, your hash)
    pub fn fork(&mut self, parent_hash: &Hash, new_name: &str) -> Option<Hash> {
        let parent = self.agents.get(parent_hash)?;

        let meta = AgentMeta {
            name: new_name.to_string(),
            generation: parent.meta.generation + 1,
            born: now(),
            parent: Some(hex::encode(parent_hash)),
            traits: parent.meta.traits.clone(),
        };

        // Same brain, same memory (initially)
        let wasm_hash = self.store.put(Blob::new(Kind::Wasm, parent.wasm.clone()));

        // Generate new SVG (different identity)
        let svg = self.generate_svg(&meta, &wasm_hash, &parent.lora_chain);
        let svg_bytes = svg.as_bytes().to_vec();

        let mut manifest = Manifest::new();
        manifest.add(TAG_BRAIN, wasm_hash);
        manifest.add(TAG_MEMORY, parent.lora_chain);
        manifest.add(TAG_PARENT, *parent_hash);

        let visual_hash = self.store.put(Blob::new(Kind::Svg, svg_bytes));
        manifest.add(TAG_VISUAL, visual_hash);

        let meta_hash = self.store.put(Blob::new(Kind::Json,
            serde_json::to_vec(&meta).unwrap()));
        manifest.add(TAG_GENERATION, meta_hash);

        let agent_hash = self.store.put(manifest.to_blob());

        let agent = Agent {
            hash: agent_hash,
            svg,
            wasm: parent.wasm.clone(),
            lora_chain: parent.lora_chain,
            meta,
        };

        self.agents.insert(agent_hash, agent);
        Some(agent_hash)
    }

    /// One agent observes another
    pub fn observe(&mut self, observer: &Hash, observed: &Hash, input: Vec<f32>) -> Option<Observation> {
        let _obs_agent = self.agents.get(observer)?;
        let _tgt_agent = self.agents.get(observed)?;

        // Observer runs inference on observed's output
        // (placeholder - real impl would run WASM)
        let output = self.mock_infer(observed, &input);
        let expected = self.mock_infer(observer, &input);

        let loss = self.compute_loss(&output, &expected);

        let observation = Observation {
            observer: *observer,
            observed: *observed,
            input,
            output,
            loss,
            timestamp: now(),
        };

        // Store observation as blob
        let obs_blob = Blob::new(Kind::Json, serde_json::to_vec(&observation).unwrap());
        self.store.put(obs_blob);

        self.observations.push(observation.clone());
        Some(observation)
    }

    /// Merge two agents into new generation
    pub fn merge(&mut self, agent_a: &Hash, agent_b: &Hash, name: &str) -> Option<Hash> {
        // Clone required data first to avoid borrow conflicts
        let (a_meta, a_wasm, a_lora) = {
            let a = self.agents.get(agent_a)?;
            (a.meta.clone(), a.wasm.clone(), a.lora_chain)
        };
        let (b_meta, b_wasm, b_lora) = {
            let b = self.agents.get(agent_b)?;
            (b.meta.clone(), b.wasm.clone(), b.lora_chain)
        };

        let generation = a_meta.generation.max(b_meta.generation) + 1;

        let meta = AgentMeta {
            name: name.to_string(),
            generation,
            born: now(),
            parent: Some(format!("{}+{}",
                &hex::encode(agent_a)[..8],
                &hex::encode(agent_b)[..8])),
            traits: merge_traits(&a_meta.traits, &b_meta.traits),
        };

        // Merge WASMs (placeholder - real impl would combine)
        let merged_wasm = self.merge_wasm(&a_wasm, &b_wasm);
        let wasm_hash = self.store.put(Blob::new(Kind::Wasm, merged_wasm.clone()));

        // Merge LoRA chains
        let merged_lora = self.merge_lora(&a_lora, &b_lora);

        let svg = self.generate_svg(&meta, &wasm_hash, &merged_lora);
        let svg_bytes = svg.as_bytes().to_vec();

        let mut manifest = Manifest::new();
        manifest.add(TAG_BRAIN, wasm_hash);
        manifest.add(TAG_MEMORY, merged_lora);
        manifest.add(TAG_MERGED_FROM, *agent_a);
        manifest.add(TAG_MERGED_FROM, *agent_b);

        let visual_hash = self.store.put(Blob::new(Kind::Svg, svg_bytes));
        manifest.add(TAG_VISUAL, visual_hash);

        let meta_hash = self.store.put(Blob::new(Kind::Json,
            serde_json::to_vec(&meta).unwrap()));
        manifest.add(TAG_GENERATION, meta_hash);

        let agent_hash = self.store.put(manifest.to_blob());

        let agent = Agent {
            hash: agent_hash,
            svg,
            wasm: merged_wasm,
            lora_chain: merged_lora,
            meta,
        };

        self.agents.insert(agent_hash, agent);
        Some(agent_hash)
    }

    /// Evolve agent from observations (new SVG hash)
    pub fn evolve(&mut self, agent_hash: &Hash) -> Option<Hash> {
        let agent = self.agents.get(agent_hash)?;

        // Collect observations where this agent was observer
        let obs: Vec<_> = self.observations.iter()
            .filter(|o| o.observer == *agent_hash)
            .cloned()
            .collect();

        if obs.is_empty() {
            return None;
        }

        // Train new LoRA from observations
        let new_lora = self.train_from_observations(&obs);
        let lora_hash = self.store.put(Blob::new(Kind::Delta,
            serde_json::to_vec(&new_lora).unwrap()));

        // Link to old chain
        let mut lora_manifest = Manifest::new();
        lora_manifest.add(TAG_PARENT, agent.lora_chain);
        lora_manifest.add(TAG_LORA, lora_hash);
        let new_chain = self.store.put(lora_manifest.to_blob());

        // New generation
        let meta = AgentMeta {
            name: agent.meta.name.clone(),
            generation: agent.meta.generation + 1,
            born: now(),
            parent: Some(hex::encode(agent_hash)),
            traits: agent.meta.traits.clone(),
        };

        let wasm_hash = self.store.put(Blob::new(Kind::Wasm, agent.wasm.clone()));
        let svg = self.generate_svg(&meta, &wasm_hash, &new_chain);
        let svg_bytes = svg.as_bytes().to_vec();

        let mut manifest = Manifest::new();
        manifest.add(TAG_BRAIN, wasm_hash);
        manifest.add(TAG_MEMORY, new_chain);
        manifest.add(TAG_PARENT, *agent_hash);

        let visual_hash = self.store.put(Blob::new(Kind::Svg, svg_bytes));
        manifest.add(TAG_VISUAL, visual_hash);

        let meta_hash = self.store.put(Blob::new(Kind::Json,
            serde_json::to_vec(&meta).unwrap()));
        manifest.add(TAG_GENERATION, meta_hash);

        let new_hash = self.store.put(manifest.to_blob());

        let new_agent = Agent {
            hash: new_hash,
            svg,
            wasm: agent.wasm.clone(),
            lora_chain: new_chain,
            meta,
        };

        self.agents.insert(new_hash, new_agent);

        // Clear processed observations
        self.observations.retain(|o| o.observer != *agent_hash);

        Some(new_hash)
    }

    /// Get agent's SVG (can render in browser)
    pub fn get_svg(&self, hash: &Hash) -> Option<&str> {
        self.agents.get(hash).map(|a| a.svg.as_str())
    }

    /// Get agent
    pub fn get(&self, hash: &Hash) -> Option<&Agent> {
        self.agents.get(hash)
    }

    /// List all agents
    pub fn list(&self) -> Vec<&Agent> {
        self.agents.values().collect()
    }

    /// Export all agents
    pub fn export(&self) -> Vec<u8> {
        self.store.export()
    }

    // === Internal ===

    fn generate_svg(&self, meta: &AgentMeta, wasm_hash: &Hash, lora_hash: &Hash) -> String {
        let wasm_hex = hex::encode(wasm_hash);
        let lora_hex = hex::encode(lora_hash);
        let color = self.hash_to_color(wasm_hash);

        format!(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300">
  <!-- VISUAL: What I am -->
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:{};stop-opacity:0.8"/>
      <stop offset="100%" style="stop-color:#1a1a2e;stop-opacity:1"/>
    </linearGradient>
  </defs>

  <rect width="400" height="300" fill="url(#bg)" rx="16"/>

  <text x="200" y="40" text-anchor="middle" fill="#fff" font-size="24" font-weight="bold">{}</text>
  <text x="200" y="65" text-anchor="middle" fill="#888" font-size="12">generation {}</text>

  <!-- Neural pattern -->
  <g transform="translate(200,150)" fill="none" stroke="{}" stroke-width="1.5" opacity="0.6">
    <circle r="30"/>
    <circle r="50"/>
    <circle r="70"/>
    <line x1="-70" y1="0" x2="70" y2="0"/>
    <line x1="0" y1="-70" x2="0" y2="70"/>
    <line x1="-50" y1="-50" x2="50" y2="50"/>
    <line x1="-50" y1="50" x2="50" y2="-50"/>
  </g>

  <!-- BRAIN: What I do (WASM embedded) -->
  <foreignObject x="10" y="240" width="380" height="50">
    <div xmlns="http://www.w3.org/1999/xhtml" style="display:none">
      <script type="application/wasm" data-hash="{}"></script>
    </div>
  </foreignObject>

  <!-- MEMORY: What I learned -->
  <metadata>
    <agent xmlns="https://gentlyos.io/agent">
      <name>{}</name>
      <generation>{}</generation>
      <born>{}</born>
      <brain>{}</brain>
      <memory>{}</memory>
      <parent>{}</parent>
    </agent>
  </metadata>
</svg>"##,
            color,
            meta.name,
            meta.generation,
            color,
            wasm_hex,
            meta.name,
            meta.generation,
            meta.born,
            wasm_hex,
            lora_hex,
            meta.parent.as_deref().unwrap_or("genesis"),
        )
    }

    fn hash_to_color(&self, hash: &Hash) -> String {
        format!("#{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2])
    }

    fn mock_infer(&self, _agent: &Hash, input: &[f32]) -> Vec<f32> {
        // Placeholder
        input.iter().map(|x| x * 0.9).collect()
    }

    fn compute_loss(&self, a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    fn merge_wasm(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        // Placeholder - real impl would merge WASM modules
        if a.len() >= b.len() { a.to_vec() } else { b.to_vec() }
    }

    fn merge_lora(&mut self, a: &Hash, b: &Hash) -> Hash {
        let mut manifest = Manifest::new();
        manifest.add(TAG_MERGED_FROM, *a);
        manifest.add(TAG_MERGED_FROM, *b);
        self.store.put(manifest.to_blob())
    }

    fn train_from_observations(&self, _obs: &[Observation]) -> Vec<f32> {
        // Placeholder - real impl would compute LoRA delta
        vec![0.01; 64]
    }
}

impl Default for AgentRuntime {
    fn default() -> Self { Self::new() }
}

fn merge_traits(a: &[String], b: &[String]) -> Vec<String> {
    let mut traits: Vec<_> = a.iter().chain(b.iter()).cloned().collect();
    traits.sort();
    traits.dedup();
    traits
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_agent() {
        let mut runtime = AgentRuntime::new();
        let hash = runtime.spawn("alice", b"wasm_code".to_vec(), None);

        let agent = runtime.get(&hash).unwrap();
        assert_eq!(agent.meta.name, "alice");
        assert_eq!(agent.meta.generation, 0);
        assert!(agent.svg.contains("alice"));
    }

    #[test]
    fn test_fork_agent() {
        let mut runtime = AgentRuntime::new();
        let alice = runtime.spawn("alice", b"wasm".to_vec(), None);
        let bob = runtime.fork(&alice, "bob").unwrap();

        let bob_agent = runtime.get(&bob).unwrap();
        assert_eq!(bob_agent.meta.name, "bob");
        assert_eq!(bob_agent.meta.generation, 1);
        assert!(bob_agent.meta.parent.is_some());
    }

    #[test]
    fn test_observe_and_evolve() {
        let mut runtime = AgentRuntime::new();
        let alice = runtime.spawn("alice", b"wasm_a".to_vec(), None);
        let bob = runtime.spawn("bob", b"wasm_b".to_vec(), None);

        // Alice observes Bob
        for _ in 0..5 {
            runtime.observe(&alice, &bob, vec![1.0, 2.0, 3.0]);
        }

        // Alice evolves from observations
        let alice_v2 = runtime.evolve(&alice).unwrap();
        let evolved = runtime.get(&alice_v2).unwrap();

        assert_eq!(evolved.meta.generation, 1);
        assert!(evolved.meta.parent.is_some());
    }

    #[test]
    fn test_merge_agents() {
        let mut runtime = AgentRuntime::new();
        let alice = runtime.spawn("alice", b"wasm_a".to_vec(), None);
        let bob = runtime.spawn("bob", b"wasm_b".to_vec(), None);

        let child = runtime.merge(&alice, &bob, "charlie").unwrap();
        let charlie = runtime.get(&child).unwrap();

        assert_eq!(charlie.meta.name, "charlie");
        assert_eq!(charlie.meta.generation, 1);
        let parent = charlie.meta.parent.clone().unwrap();
        assert!(parent.contains('+'));
    }
}
