//! ASCII Tree Renderer

use crate::tree::ProjectTree;

pub struct AsciiTreeRenderer {
    pub use_unicode: bool,
    pub show_state: bool,
    pub show_ideas: bool,
}

impl Default for AsciiTreeRenderer {
    fn default() -> Self {
        Self {
            use_unicode: true,
            show_state: true,
            show_ideas: true,
        }
    }
}

impl AsciiTreeRenderer {
    pub fn render(&self, tree: &ProjectTree) -> String {
        tree.render_ascii()
    }
}
