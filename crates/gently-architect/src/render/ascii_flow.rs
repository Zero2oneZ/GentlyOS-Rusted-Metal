//! ASCII Flowchart Renderer

use crate::flow::FlowChart;

pub struct AsciiFlowRenderer {
    pub max_width: usize,
    pub show_state: bool,
}

impl Default for AsciiFlowRenderer {
    fn default() -> Self {
        Self {
            max_width: 80,
            show_state: true,
        }
    }
}

impl AsciiFlowRenderer {
    pub fn render(&self, flow: &FlowChart) -> String {
        flow.render_ascii()
    }
}
