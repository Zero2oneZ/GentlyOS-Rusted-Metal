//! Project Tree
//!
//! File/folder structure mapped from crystallized ideas.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// File/folder tree mapped from ideas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTree {
    pub name: String,
    pub root: PathBuf,
    pub nodes: HashMap<PathBuf, TreeNode>,
    pub idea_links: HashMap<PathBuf, Vec<Uuid>>,
}

impl ProjectTree {
    /// Create a new project tree
    pub fn new(name: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let mut nodes = HashMap::new();

        // Add root node
        nodes.insert(
            root.clone(),
            TreeNode {
                path: root.clone(),
                kind: NodeKind::Directory,
                state: NodeState::Planned,
                source_ideas: Vec::new(),
            },
        );

        Self {
            name: name.into(),
            root,
            nodes,
            idea_links: HashMap::new(),
        }
    }

    /// Add a directory
    pub fn add_dir(&mut self, path: impl Into<PathBuf>) -> &mut TreeNode {
        let path = path.into();
        self.nodes.entry(path.clone()).or_insert_with(|| TreeNode {
            path: path.clone(),
            kind: NodeKind::Directory,
            state: NodeState::Planned,
            source_ideas: Vec::new(),
        });
        self.nodes.get_mut(&path).unwrap()
    }

    /// Add a file
    pub fn add_file(&mut self, path: impl Into<PathBuf>, language: impl Into<String>) -> &mut TreeNode {
        let path = path.into();
        self.nodes.entry(path.clone()).or_insert_with(|| TreeNode {
            path: path.clone(),
            kind: NodeKind::File {
                language: language.into(),
            },
            state: NodeState::Planned,
            source_ideas: Vec::new(),
        });
        self.nodes.get_mut(&path).unwrap()
    }

    /// Link an idea to a path
    pub fn link_idea(&mut self, path: impl Into<PathBuf>, idea_id: Uuid) {
        let path = path.into();
        self.idea_links
            .entry(path.clone())
            .or_default()
            .push(idea_id);

        if let Some(node) = self.nodes.get_mut(&path) {
            if !node.source_ideas.contains(&idea_id) {
                node.source_ideas.push(idea_id);
            }
        }
    }

    /// Get all children of a directory
    pub fn children(&self, dir: &Path) -> Vec<&TreeNode> {
        self.nodes
            .values()
            .filter(|n| {
                n.path.parent() == Some(dir) && n.path != dir
            })
            .collect()
    }

    /// Render as ASCII tree
    pub fn render_ascii(&self) -> String {
        let mut lines = Vec::new();
        self.render_node(&self.root, "", true, &mut lines);
        lines.join("\n")
    }

    fn render_node(&self, path: &Path, prefix: &str, is_last: bool, lines: &mut Vec<String>) {
        let node = match self.nodes.get(path) {
            Some(n) => n,
            None => return,
        };

        let connector = if prefix.is_empty() {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };

        let name = path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        let state_indicator = node.state_indicator();
        let kind_suffix = match &node.kind {
            NodeKind::Directory => "/",
            NodeKind::File { .. } => "",
        };

        let idea_link = if !node.source_ideas.is_empty() {
            format!(" ← idea #{}", node.source_ideas.len())
        } else {
            String::new()
        };

        lines.push(format!(
            "{}{}{}{} {} {}",
            prefix,
            connector,
            name,
            kind_suffix,
            state_indicator,
            idea_link
        ));

        // Render children
        let child_prefix = if prefix.is_empty() {
            String::new()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        let mut children: Vec<_> = self.children(path);
        children.sort_by(|a, b| {
            // Directories first, then files
            match (&a.kind, &b.kind) {
                (NodeKind::Directory, NodeKind::File { .. }) => std::cmp::Ordering::Less,
                (NodeKind::File { .. }, NodeKind::Directory) => std::cmp::Ordering::Greater,
                _ => a.path.cmp(&b.path),
            }
        });

        for (i, child) in children.iter().enumerate() {
            let is_last_child = i == children.len() - 1;
            self.render_node(&child.path, &child_prefix, is_last_child, lines);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> TreeStats {
        let mut stats = TreeStats::default();

        for node in self.nodes.values() {
            match node.kind {
                NodeKind::Directory => stats.directories += 1,
                NodeKind::File { .. } => stats.files += 1,
            }

            match node.state {
                NodeState::Planned => stats.planned += 1,
                NodeState::Confirmed => stats.confirmed += 1,
                NodeState::Created => stats.created += 1,
                NodeState::Locked => stats.locked += 1,
            }
        }

        stats
    }
}

/// A node in the project tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub path: PathBuf,
    pub kind: NodeKind,
    pub state: NodeState,
    pub source_ideas: Vec<Uuid>,
}

impl TreeNode {
    /// Confirm this node
    pub fn confirm(&mut self) {
        self.state = NodeState::Confirmed;
    }

    /// Mark as created
    pub fn create(&mut self) {
        self.state = NodeState::Created;
    }

    /// Lock this node
    pub fn lock(&mut self) {
        self.state = NodeState::Locked;
    }

    /// State indicator for display
    pub fn state_indicator(&self) -> &'static str {
        match self.state {
            NodeState::Planned => "···",
            NodeState::Confirmed => "▓▓▓",
            NodeState::Created => "███",
            NodeState::Locked => "🔒",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeKind {
    Directory,
    File { language: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    /// In the tree but not created
    Planned,
    /// User approved structure
    Confirmed,
    /// File/directory exists
    Created,
    /// XOR locked
    Locked,
}

#[derive(Debug, Default)]
pub struct TreeStats {
    pub directories: usize,
    pub files: usize,
    pub planned: usize,
    pub confirmed: usize,
    pub created: usize,
    pub locked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_tree() {
        let mut tree = ProjectTree::new("auth-system", "auth-system");

        tree.add_dir("auth-system/src");
        tree.add_dir("auth-system/src/providers");
        tree.add_file("auth-system/src/providers/oauth.rs", "rust");
        tree.add_file("auth-system/src/lib.rs", "rust");

        let idea_id = Uuid::new_v4();
        tree.link_idea("auth-system/src/providers/oauth.rs", idea_id);

        let ascii = tree.render_ascii();
        assert!(ascii.contains("oauth.rs"));
        assert!(ascii.contains("providers/"));
    }

    #[test]
    fn test_tree_stats() {
        let mut tree = ProjectTree::new("test", "test");
        tree.add_dir("test/src");
        tree.add_file("test/src/main.rs", "rust");

        let stats = tree.stats();
        assert_eq!(stats.directories, 2); // root + src
        assert_eq!(stats.files, 1);
    }
}
