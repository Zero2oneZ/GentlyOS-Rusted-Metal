//! Main TUI Application

use crate::crystal::IdeaCrystal;
use crate::flow::FlowChart;
use crate::recall::RecallEngine;
use crate::security::ArchitectSecurity;
use crate::tree::ProjectTree;

/// The main Architect Coder application
pub struct ArchitectApp {
    pub recall: RecallEngine,
    pub security: ArchitectSecurity,
    pub tree: Option<ProjectTree>,
    pub flow: Option<FlowChart>,
    pub current_view: View,
    pub running: bool,
    pub input_buffer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Ideas,  // F1
    Tree,   // F2
    Flow,   // F3
    Logs,   // F4
    Lock,   // F5
}

impl ArchitectApp {
    pub fn new() -> Self {
        Self {
            recall: RecallEngine::new(),
            security: ArchitectSecurity::new(),
            tree: None,
            flow: None,
            current_view: View::Ideas,
            running: true,
            input_buffer: String::new(),
        }
    }

    pub fn switch_view(&mut self, view: View) {
        self.current_view = view;
    }

    pub fn add_idea(&mut self, content: &str) {
        let crystal = IdeaCrystal::spoken(content);
        self.recall.add(crystal);
    }

    pub fn recall(&mut self, query: &str) -> String {
        let result = self.recall.recall(query);
        self.recall.format_result(&result)
    }

    pub fn create_tree(&mut self, name: &str, root: &str) {
        self.tree = Some(ProjectTree::new(name, root));
    }

    pub fn create_flow(&mut self, topic: &str) {
        self.flow = Some(FlowChart::new(topic));
    }

    pub fn quit(&mut self) {
        self.security.end_session();
        self.running = false;
    }
}

impl Default for ArchitectApp {
    fn default() -> Self {
        Self::new()
    }
}
