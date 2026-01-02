//! SVG Builder for exports

use crate::flow::FlowChart;
use crate::tree::ProjectTree;

pub struct SvgBuilder {
    width: u32,
    height: u32,
    content: Vec<String>,
}

impl SvgBuilder {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            content: Vec::new(),
        }
    }

    pub fn from_flowchart(flow: &FlowChart) -> String {
        flow.to_svg()
    }

    pub fn from_tree(_tree: &ProjectTree) -> String {
        // TODO: Implement tree to SVG
        String::from("<svg></svg>")
    }

    pub fn build(&self) -> String {
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">{}</svg>"#,
            self.width,
            self.height,
            self.content.join("\n")
        )
    }
}
