//! Living Feed - the core self-tracking context system
//!
//! Maintains a feed of items that automatically rotate based on engagement.
//! Items have charge that decays over time and gets boosted when mentioned.

use crate::{
    bridge::{Bridge, BridgeDetector, BridgeKind},
    extractor::{ContextExtractor, ExtractedContext},
    item::{FeedItem, ItemKind, ItemState},
    persistence::FeedState,
    xor_chain::XorChain,
};
use std::collections::HashMap;
use uuid::Uuid;

/// The Living Feed - self-tracking context system
#[derive(Debug, Clone)]
pub struct LivingFeed {
    /// All feed items
    items: Vec<FeedItem>,

    /// All bridges between items
    bridges: Vec<Bridge>,

    /// XOR chain for message linking
    xor_chain: XorChain,

    /// Context extractor
    extractor: ContextExtractor,

    /// Bridge detector
    bridge_detector: BridgeDetector,

    /// Focus stack (item IDs in order of attention)
    focus_stack: Vec<Uuid>,

    /// Total interaction count
    interaction_count: u64,

    /// Name to ID lookup cache
    name_index: HashMap<String, Uuid>,
}

impl Default for LivingFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl LivingFeed {
    /// Create a new empty feed
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            bridges: Vec::new(),
            xor_chain: XorChain::new(),
            extractor: ContextExtractor::new(),
            bridge_detector: BridgeDetector::default(),
            focus_stack: Vec::new(),
            interaction_count: 0,
            name_index: HashMap::new(),
        }
    }

    /// Create feed from persisted state
    pub fn from_state(state: FeedState) -> Self {
        let mut feed = Self {
            items: state.items,
            bridges: state.bridges,
            xor_chain: state.xor_chain,
            extractor: ContextExtractor::new(),
            bridge_detector: BridgeDetector::default(),
            focus_stack: Vec::new(),
            interaction_count: state.interaction_count,
            name_index: HashMap::new(),
        };

        // Rebuild indices
        feed.rebuild_indices();

        feed
    }

    /// Convert to persistable state
    pub fn to_state(&self) -> FeedState {
        FeedState {
            version: 1,
            items: self.items.clone(),
            bridges: self.bridges.clone(),
            xor_chain: self.xor_chain.clone(),
            last_tick: chrono::Utc::now().timestamp_millis() as u64,
            interaction_count: self.interaction_count,
        }
    }

    /// Rebuild internal indices
    fn rebuild_indices(&mut self) {
        self.name_index.clear();
        for item in &self.items {
            self.name_index
                .insert(item.name.to_lowercase(), item.id);
        }

        // Update extractor with known items
        self.extractor
            .set_known_items(self.items.iter().map(|i| i.name.to_lowercase()));

        // Rebuild focus stack from charge order
        let mut sorted: Vec<_> = self
            .items
            .iter()
            .filter(|i| !i.archived)
            .map(|i| (i.id, i.charge))
            .collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.focus_stack = sorted.into_iter().map(|(id, _)| id).collect();
    }

    // ============== Item Management ==============

    /// Add a new item to the feed
    pub fn add_item(&mut self, name: impl Into<String>, kind: ItemKind) -> Uuid {
        let name = name.into();
        let item = FeedItem::new(&name, kind);
        let id = item.id;

        self.name_index.insert(name.to_lowercase(), id);
        self.focus_stack.insert(0, id); // New items go to top
        self.items.push(item);

        // Update extractor
        self.extractor.add_known_items([name.to_lowercase()]);

        id
    }

    /// Get item by ID
    pub fn get_item(&self, id: Uuid) -> Option<&FeedItem> {
        self.items.iter().find(|i| i.id == id)
    }

    /// Get item by ID (mutable)
    pub fn get_item_mut(&mut self, id: Uuid) -> Option<&mut FeedItem> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    /// Get item by ID
    pub fn get_item_by_id(&self, id: Uuid) -> Option<&FeedItem> {
        self.get_item(id)
    }

    /// Get item by name (case-insensitive)
    pub fn get_item_by_name(&self, name: &str) -> Option<&FeedItem> {
        self.name_index
            .get(&name.to_lowercase())
            .and_then(|id| self.get_item(*id))
    }

    /// Get item by name (mutable)
    pub fn get_item_by_name_mut(&mut self, name: &str) -> Option<&mut FeedItem> {
        if let Some(&id) = self.name_index.get(&name.to_lowercase()) {
            self.get_item_mut(id)
        } else {
            None
        }
    }

    /// Get all items
    pub fn items(&self) -> &[FeedItem] {
        &self.items
    }

    /// Get all bridges
    pub fn bridges(&self) -> &[Bridge] {
        &self.bridges
    }

    /// Remove an item
    pub fn remove_item(&mut self, id: Uuid) -> Option<FeedItem> {
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            let item = self.items.remove(pos);
            self.name_index.remove(&item.name.to_lowercase());
            self.focus_stack.retain(|i| *i != id);
            self.bridges.retain(|b| !b.connects(id));
            Some(item)
        } else {
            None
        }
    }

    // ============== Charge Operations ==============

    /// Boost an item's charge
    pub fn boost(&mut self, name: &str, amount: f32) -> bool {
        if let Some(item) = self.get_item_by_name_mut(name) {
            item.boost(amount);

            // Move to top of focus stack
            let id = item.id;
            self.focus_stack.retain(|i| *i != id);
            self.focus_stack.insert(0, id);

            true
        } else {
            false
        }
    }

    /// Decay all items
    pub fn decay_all(&mut self) {
        for item in &mut self.items {
            item.decay();
        }
    }

    /// Freeze an item (set charge to 0)
    pub fn freeze(&mut self, name: &str) -> bool {
        if let Some(item) = self.get_item_by_name_mut(name) {
            item.charge = 0.0;
            item.update_state();
            true
        } else {
            false
        }
    }

    /// Archive an item
    pub fn archive(&mut self, name: &str) -> bool {
        if let Some(item) = self.get_item_by_name_mut(name) {
            item.archive();
            let id = item.id;
            self.focus_stack.retain(|i| *i != id);
            true
        } else {
            false
        }
    }

    // ============== Step Management ==============

    /// Add a step to an item
    pub fn add_step(&mut self, item_name: &str, step_content: impl Into<String>) -> Option<u32> {
        self.get_item_by_name_mut(item_name)
            .map(|item| item.add_step(step_content))
    }

    /// Complete a step
    pub fn complete_step(&mut self, item_name: &str, step_id: u32) -> bool {
        self.get_item_by_name_mut(item_name)
            .map(|item| item.complete_step(step_id))
            .unwrap_or(false)
    }

    // ============== Bridge Operations ==============

    /// Create or reinforce a bridge between items
    pub fn bridge(&mut self, name1: &str, name2: &str, kind: BridgeKind) -> bool {
        let id1 = match self.name_index.get(&name1.to_lowercase()) {
            Some(&id) => id,
            None => return false,
        };

        let id2 = match self.name_index.get(&name2.to_lowercase()) {
            Some(&id) => id,
            None => return false,
        };

        // Check if bridge already exists
        if let Some(bridge) = self.bridges.iter_mut().find(|b| b.connects_pair(id1, id2)) {
            bridge.reinforce();
        } else {
            self.bridges.push(Bridge::new(id1, id2, kind));
        }

        true
    }

    /// Get bridges for an item
    pub fn bridges_for(&self, name: &str) -> Vec<&Bridge> {
        if let Some(&id) = self.name_index.get(&name.to_lowercase()) {
            self.bridges.iter().filter(|b| b.connects(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Get recent bridges (by last reinforced)
    pub fn recent_bridges(&self, limit: usize) -> Vec<&Bridge> {
        let mut bridges: Vec<_> = self.bridges.iter().collect();
        bridges.sort_by(|a, b| b.last_reinforced.cmp(&a.last_reinforced));
        bridges.into_iter().take(limit).collect()
    }

    // ============== Context Processing ==============

    /// Process a context update (the main tick loop)
    pub fn tick(&mut self, ctx: &ExtractedContext) {
        self.interaction_count += 1;

        // 1. Decay all charges
        self.decay_all();

        // 2. Boost mentioned items
        let boost_multiplier = ctx.sentiment.boost_multiplier();
        for mention in &ctx.mentions {
            if let Some(item) = self.get_item_by_name_mut(mention) {
                item.boost(0.3 * boost_multiplier);
            }
        }

        // 3. Process bridge candidates
        for (name1, name2) in &ctx.bridge_candidates {
            self.bridge(name1, name2, BridgeKind::Mention);
        }

        // 4. Add action items as steps to current focus
        if !ctx.action_items.is_empty() {
            if let Some(&focus_id) = self.focus_stack.first() {
                if let Some(item) = self.get_item_mut(focus_id) {
                    for action in &ctx.action_items {
                        item.add_step(action);
                    }
                }
            }
        }

        // 5. Auto-rotate if needed (promote highest cooling if no hot)
        self.auto_rotate();

        // 6. Update focus stack order
        self.reorder_focus_stack();
    }

    /// Process text directly (extracts context then ticks)
    pub fn process(&mut self, text: &str) {
        let ctx = self.extractor.extract(text);
        self.tick(&ctx);
    }

    /// Process command + output
    pub fn process_command(&mut self, command: &str, output: &str) {
        // Advance XOR chain
        self.xor_chain.advance(&format!("{}:{}", command, output));

        let ctx = self.extractor.from_command(command, output);
        self.tick(&ctx);
    }

    /// Auto-rotate: if no hot items, promote the highest cooling item
    fn auto_rotate(&mut self) {
        let has_hot = self.items.iter().any(|i| !i.archived && i.charge > 0.8);

        if !has_hot {
            // Find highest charge cooling item
            if let Some(item) = self
                .items
                .iter_mut()
                .filter(|i| !i.archived && i.charge > 0.1 && i.charge <= 0.4)
                .max_by(|a, b| a.charge.partial_cmp(&b.charge).unwrap())
            {
                item.boost(0.5); // Promote to active/hot
            }
        }
    }

    /// Reorder focus stack by charge
    fn reorder_focus_stack(&mut self) {
        let mut items: Vec<_> = self
            .items
            .iter()
            .filter(|i| !i.archived)
            .map(|i| (i.id, i.charge))
            .collect();

        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.focus_stack = items.into_iter().map(|(id, _)| id).collect();
    }

    // ============== Query Operations ==============

    /// Get hot items (charge > 0.8)
    pub fn hot_items(&self) -> Vec<&FeedItem> {
        self.items
            .iter()
            .filter(|i| !i.archived && i.state == ItemState::Hot)
            .collect()
    }

    /// Get active items (charge 0.4-0.8)
    pub fn active_items(&self) -> Vec<&FeedItem> {
        self.items
            .iter()
            .filter(|i| !i.archived && i.state == ItemState::Active)
            .collect()
    }

    /// Get cooling items (charge 0.1-0.4)
    pub fn cooling_items(&self) -> Vec<&FeedItem> {
        self.items
            .iter()
            .filter(|i| !i.archived && i.state == ItemState::Cooling)
            .collect()
    }

    /// Get frozen items (charge < 0.1)
    pub fn frozen_items(&self) -> Vec<&FeedItem> {
        self.items
            .iter()
            .filter(|i| !i.archived && i.state == ItemState::Frozen)
            .collect()
    }

    /// Get current focus item
    pub fn get_focus(&self) -> Option<&FeedItem> {
        self.focus_stack.first().and_then(|id| self.get_item(*id))
    }

    /// Get XOR chain
    pub fn xor_chain(&self) -> &XorChain {
        &self.xor_chain
    }

    // ============== Rendering ==============

    /// Render feed summary
    pub fn render_summary(&self) -> String {
        let mut out = String::new();

        let hot = self.hot_items();
        if !hot.is_empty() {
            out.push_str("🔥 HOT\n");
            for item in hot {
                out.push_str(&format!("  • {}\n", item.render_compact()));
            }
        }

        let active = self.active_items();
        if !active.is_empty() {
            out.push_str("⚡ ACTIVE\n");
            for item in active {
                out.push_str(&format!("  • {}\n", item.render_compact()));
            }
        }

        let cooling = self.cooling_items();
        if !cooling.is_empty() {
            out.push_str("💤 COOLING\n");
            for item in cooling {
                out.push_str(&format!("  • {}\n", item.render_compact()));
            }
        }

        if out.is_empty() {
            out.push_str("(empty feed)");
        }

        out
    }

    /// Render full feed with bridges
    pub fn render_full(&self) -> String {
        let mut out = self.render_summary();

        let bridges = self.recent_bridges(5);
        if !bridges.is_empty() {
            out.push_str("\n🔗 BRIDGES\n");
            for bridge in bridges {
                if let (Some(from), Some(to)) =
                    (self.get_item(bridge.from_id), self.get_item(bridge.to_id))
                {
                    out.push_str(&format!(
                        "  {}\n",
                        bridge.render_compact(&from.name, &to.name)
                    ));
                }
            }
        }

        out.push_str(&format!("\n{}\n", self.xor_chain.render()));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_basics() {
        let mut feed = LivingFeed::new();

        let id = feed.add_item("Test Project", ItemKind::Project);
        assert!(feed.get_item(id).is_some());
        assert!(feed.get_item_by_name("test project").is_some());

        assert_eq!(feed.hot_items().len(), 1);
    }

    #[test]
    fn test_feed_tick() {
        let mut feed = LivingFeed::new();
        feed.add_item("GentlyOS", ItemKind::Project);
        feed.add_item("BoneBlob", ItemKind::Project);

        // Process text mentioning both
        feed.process("Working on GentlyOS and BoneBlob integration");

        // Both should be boosted
        assert!(feed.get_item_by_name("gentlyos").unwrap().charge > 0.9);
        assert!(feed.get_item_by_name("boneblob").unwrap().charge > 0.9);

        // Bridge should be created
        assert_eq!(feed.bridges.len(), 1);
    }

    #[test]
    fn test_auto_rotate() {
        let mut feed = LivingFeed::new();
        feed.add_item("Test", ItemKind::Project);

        // Decay until cooling
        for _ in 0..30 {
            feed.decay_all();
        }

        assert!(feed.get_item_by_name("test").unwrap().charge < 0.4);

        // Tick should auto-rotate
        feed.tick(&ExtractedContext::default());

        // Should be boosted
        assert!(feed.get_item_by_name("test").unwrap().charge > 0.4);
    }

    #[test]
    fn test_steps() {
        let mut feed = LivingFeed::new();
        feed.add_item("Project", ItemKind::Project);

        feed.add_step("project", "Step 1");
        feed.add_step("project", "Step 2");

        let item = feed.get_item_by_name("project").unwrap();
        assert_eq!(item.pending_steps().len(), 2);

        feed.complete_step("project", 1);
        let item = feed.get_item_by_name("project").unwrap();
        assert_eq!(item.pending_steps().len(), 1);
    }
}
