//! Flowchart Representation
//!
//! ASCII and SVG flowcharts for idea visualization.

use crate::crystal::IdeaState;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A flowchart representing idea connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowChart {
    pub id: Uuid,
    pub topic: String,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
}

impl FlowChart {
    /// Create a new flowchart
    pub fn new(topic: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            topic: topic.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a node
    pub fn add_node(&mut self, label: impl Into<String>, kind: FlowNodeKind) -> Uuid {
        let node = FlowNode {
            id: Uuid::new_v4(),
            label: label.into(),
            kind,
            idea_link: None,
            state: IdeaState::Spoken,
            position: (0, 0),
        };
        let id = node.id;
        self.nodes.push(node);
        id
    }

    /// Add a start node
    pub fn add_start(&mut self, label: impl Into<String>) -> Uuid {
        self.add_node(label, FlowNodeKind::Start)
    }

    /// Add an end node
    pub fn add_end(&mut self, label: impl Into<String>) -> Uuid {
        self.add_node(label, FlowNodeKind::End)
    }

    /// Add a process node
    pub fn add_process(&mut self, label: impl Into<String>) -> Uuid {
        self.add_node(label, FlowNodeKind::Process)
    }

    /// Add a decision node
    pub fn add_decision(&mut self, label: impl Into<String>) -> Uuid {
        self.add_node(label, FlowNodeKind::Decision)
    }

    /// Connect two nodes
    pub fn connect(&mut self, from: Uuid, to: Uuid) {
        self.edges.push(FlowEdge {
            from,
            to,
            label: None,
            kind: EdgeKind::Normal,
        });
    }

    /// Connect with yes/no branches
    pub fn connect_yes(&mut self, from: Uuid, to: Uuid) {
        self.edges.push(FlowEdge {
            from,
            to,
            label: Some("yes".into()),
            kind: EdgeKind::Yes,
        });
    }

    pub fn connect_no(&mut self, from: Uuid, to: Uuid) {
        self.edges.push(FlowEdge {
            from,
            to,
            label: Some("no".into()),
            kind: EdgeKind::No,
        });
    }

    /// Get a node by ID
    pub fn get_node(&self, id: Uuid) -> Option<&FlowNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Get a mutable node by ID
    pub fn get_node_mut(&mut self, id: Uuid) -> Option<&mut FlowNode> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    /// Link a node to an idea
    pub fn link_idea(&mut self, node_id: Uuid, idea_id: Uuid) {
        if let Some(node) = self.get_node_mut(node_id) {
            node.idea_link = Some(idea_id);
        }
    }

    /// Confirm a node
    pub fn confirm_node(&mut self, node_id: Uuid) {
        if let Some(node) = self.get_node_mut(node_id) {
            node.state = IdeaState::Confirmed;
        }
    }

    /// Auto-layout nodes for ASCII rendering
    pub fn auto_layout(&mut self) {
        // Simple top-to-bottom layout
        let mut y = 0;
        let mut visited = std::collections::HashSet::new();

        // Find start nodes
        let start_nodes: Vec<Uuid> = self.nodes
            .iter()
            .filter(|n| matches!(n.kind, FlowNodeKind::Start))
            .map(|n| n.id)
            .collect();

        for start_id in start_nodes {
            self.layout_from(start_id, 0, &mut y, &mut visited);
        }
    }

    fn layout_from(
        &mut self,
        node_id: Uuid,
        x: i32,
        y: &mut i32,
        visited: &mut std::collections::HashSet<Uuid>,
    ) {
        if visited.contains(&node_id) {
            return;
        }
        visited.insert(node_id);

        if let Some(node) = self.get_node_mut(node_id) {
            node.position = (x, *y);
            *y += 1;
        }

        // Get outgoing edges
        let outgoing: Vec<Uuid> = self.edges
            .iter()
            .filter(|e| e.from == node_id)
            .map(|e| e.to)
            .collect();

        let mut branch_x = x;
        for (i, target) in outgoing.iter().enumerate() {
            if i > 0 {
                branch_x += 1;
            }
            self.layout_from(*target, branch_x, y, visited);
        }
    }

    /// Render as ASCII flowchart
    pub fn render_ascii(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("TOPIC: {}", self.topic));
        lines.push("═".repeat(40));
        lines.push(String::new());

        // Simple linear rendering for now
        for node in &self.nodes {
            let box_content = self.render_node_ascii(node);
            lines.push(box_content);

            // Find outgoing edges
            let outgoing: Vec<_> = self.edges
                .iter()
                .filter(|e| e.from == node.id)
                .collect();

            if !outgoing.is_empty() {
                if outgoing.len() == 1 && outgoing[0].label.is_none() {
                    lines.push("          │".to_string());
                    lines.push("          ▼".to_string());
                } else {
                    // Decision branches
                    let labels: Vec<_> = outgoing
                        .iter()
                        .map(|e| e.label.as_deref().unwrap_or(""))
                        .collect();
                    lines.push(format!("     {}/  \\{}",
                        labels.first().unwrap_or(&""),
                        labels.get(1).unwrap_or(&"")
                    ));
                    lines.push("       /    \\".to_string());
                }
            }
        }

        lines.join("\n")
    }

    fn render_node_ascii(&self, node: &FlowNode) -> String {
        let state_indicator = match node.state {
            IdeaState::Spoken => "░░░",
            IdeaState::Embedded => "▒▒▒",
            IdeaState::Confirmed => "▓▓▓",
            IdeaState::Crystallized => "███",
            _ => "···",
        };

        match node.kind {
            FlowNodeKind::Start | FlowNodeKind::End => {
                format!(
                    "      ┌────────────────────┐\n      │ {:^18} │\n      └────────────────────┘",
                    format!("{} {}", node.label, state_indicator)
                )
            }
            FlowNodeKind::Process => {
                format!(
                    "    ┌──────────────────────┐\n    │ {:^20} │\n    │ {:^20} │\n    └──────────────────────┘",
                    node.label,
                    state_indicator
                )
            }
            FlowNodeKind::Decision => {
                format!(
                    "        ┌────────────┐\n       / {:^12} \\\n      < {:^14} >\n       \\ {:^12} /\n        └────────────┘",
                    "",
                    node.label,
                    state_indicator
                )
            }
            FlowNodeKind::Data => {
                format!(
                    "    ╱──────────────────────╲\n   ╱ {:^22} ╲\n   ╲ {:^22} ╱\n    ╲──────────────────────╱",
                    node.label,
                    state_indicator
                )
            }
            FlowNodeKind::Subprocess => {
                format!(
                    "    ┌─┬────────────────┬─┐\n    │ │ {:^16} │ │\n    │ │ {:^16} │ │\n    └─┴────────────────┴─┘",
                    node.label,
                    state_indicator
                )
            }
        }
    }

    /// Export as SVG
    pub fn to_svg(&self) -> String {
        let mut svg = String::new();
        svg.push_str(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 600">"#);
        svg.push_str(r#"<style>
            .node { fill: #1a1a2e; stroke: #00ffff; stroke-width: 2; }
            .confirmed { fill: #162447; stroke: #00ff88; }
            .label { fill: #ffffff; font-family: monospace; font-size: 12px; }
            .edge { stroke: #00ffff; stroke-width: 2; fill: none; }
        </style>"#);

        // Render nodes
        for (i, node) in self.nodes.iter().enumerate() {
            let y = 50 + i * 100;
            let class = if node.state == IdeaState::Confirmed {
                "node confirmed"
            } else {
                "node"
            };

            match node.kind {
                FlowNodeKind::Start | FlowNodeKind::End => {
                    svg.push_str(&format!(
                        r#"<ellipse class="{}" cx="400" cy="{}" rx="80" ry="30"/>"#,
                        class, y
                    ));
                }
                FlowNodeKind::Decision => {
                    svg.push_str(&format!(
                        r#"<polygon class="{}" points="400,{} 480,{} 400,{} 320,{}"/>"#,
                        class, y - 30, y, y + 30, y
                    ));
                }
                _ => {
                    svg.push_str(&format!(
                        r#"<rect class="{}" x="320" y="{}" width="160" height="50" rx="5"/>"#,
                        class, y - 25
                    ));
                }
            }

            svg.push_str(&format!(
                r#"<text class="label" x="400" y="{}" text-anchor="middle">{}</text>"#,
                y + 5, node.label
            ));
        }

        svg.push_str("</svg>");
        svg
    }
}

/// A node in the flowchart
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    pub id: Uuid,
    pub label: String,
    pub kind: FlowNodeKind,
    pub idea_link: Option<Uuid>,
    pub state: IdeaState,
    pub position: (i32, i32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowNodeKind {
    Start,
    End,
    Process,
    Decision,
    Data,
    Subprocess,
}

/// An edge connecting nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEdge {
    pub from: Uuid,
    pub to: Uuid,
    pub label: Option<String>,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeKind {
    Normal,
    Yes,
    No,
    Loop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flowchart_creation() {
        let mut flow = FlowChart::new("Authentication Flow");

        let start = flow.add_start("User Request");
        let check = flow.add_decision("Has Session?");
        let login = flow.add_process("Show Login");
        let end = flow.add_end("Return Session");

        flow.connect(start, check);
        flow.connect_yes(check, end);
        flow.connect_no(check, login);

        assert_eq!(flow.nodes.len(), 4);
        assert_eq!(flow.edges.len(), 3);
    }

    #[test]
    fn test_ascii_render() {
        let mut flow = FlowChart::new("Test");
        let start = flow.add_start("START");
        flow.confirm_node(start);

        let ascii = flow.render_ascii();
        assert!(ascii.contains("START"));
        assert!(ascii.contains("▓▓▓"));
    }
}
