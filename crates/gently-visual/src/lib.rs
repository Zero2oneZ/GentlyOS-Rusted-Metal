#![allow(dead_code, unused_imports, unused_variables)]
//! # GentlyOS Visual Engine
//!
//! Generates animated SVG patterns for Dance protocol.
//!
//! Each pattern is cryptographically derived and visually distinct,
//! allowing humans to recognize their own pattern among decoys.

use gently_core::pattern::{Pattern, VisualInstruction, Color, Shape, Motion};

/// Result type for visual operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from visual operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SVG generation failed: {0}")]
    SvgError(String),

    #[error("Invalid pattern configuration")]
    InvalidPattern,
}

/// Visual engine for pattern rendering
pub struct VisualEngine {
    width: u32,
    height: u32,
}

impl VisualEngine {
    /// Create new visual engine
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// Render a pattern to SVG string
    pub fn render_svg(&self, pattern: &Pattern) -> String {
        self.render_visual_instruction(&pattern.visual)
    }

    /// Render just a visual instruction
    pub fn render_visual_instruction(&self, visual: &VisualInstruction) -> String {
        let color = visual.color.to_hex();
        let shape_svg = self.render_shape(visual.shape, &color);
        let animation = self.render_animation(visual.motion);

        let bg = "#0a0a0a";
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">
  <defs>
    <radialGradient id="glow">
      <stop offset="0%" stop-color="{color}" stop-opacity="1"/>
      <stop offset="100%" stop-color="{color}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="{bg}"/>
  <g transform="translate({cx}, {cy})">
    {shape}
    {animation}
  </g>
</svg>"#,
            w = self.width,
            h = self.height,
            cx = self.width / 2,
            cy = self.height / 2,
            color = color,
            bg = bg,
            shape = shape_svg,
            animation = animation,
        )
    }

    fn render_shape(&self, shape: Shape, color: &str) -> String {
        let size = self.width.min(self.height) as f32 * 0.3_f32;

        match shape {
            Shape::Circle => format!(
                r#"<circle r="{}" fill="{}" opacity="0.9"/>"#,
                size, color
            ),
            Shape::Hexagon => {
                let points = self.hexagon_points(size);
                format!(r#"<polygon points="{}" fill="{}" opacity="0.9"/>"#, points, color)
            }
            Shape::Triangle => {
                let points = self.triangle_points(size);
                format!(r#"<polygon points="{}" fill="{}" opacity="0.9"/>"#, points, color)
            }
            Shape::Square => format!(
                r#"<rect x="-{s}" y="-{s}" width="{d}" height="{d}" fill="{c}" opacity="0.9"/>"#,
                s = size,
                d = size * 2.0_f32,
                c = color
            ),
            Shape::Diamond => {
                let points = format!(
                    "0,-{s} {s},0 0,{s} -{s},0",
                    s = size
                );
                format!(r#"<polygon points="{}" fill="{}" opacity="0.9"/>"#, points, color)
            }
            Shape::Star => {
                let points = self.star_points(size, 5);
                format!(r#"<polygon points="{}" fill="{}" opacity="0.9"/>"#, points, color)
            }
            Shape::Wave => format!(
                r#"<path d="M-{s},0 Q-{h},{s} 0,0 T{s},0" fill="none" stroke="{c}" stroke-width="8"/>"#,
                s = size,
                h = size / 2.0_f32,
                c = color
            ),
            Shape::Spiral => format!(
                r#"<path d="M0,0 Q{s},{s} 0,{d} T-{s},0" fill="none" stroke="{c}" stroke-width="6"/>"#,
                s = size / 2.0_f32,
                d = size,
                c = color
            ),
        }
    }

    fn render_animation(&self, motion: Motion) -> String {
        match motion {
            Motion::Static => String::new(),
            Motion::Pulse => r#"<animate attributeName="opacity" values="0.9;0.3;0.9" dur="1s" repeatCount="indefinite"/>"#.to_string(),
            Motion::Rotate => r#"<animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="3s" repeatCount="indefinite"/>"#.to_string(),
            Motion::Morph => r#"<animate attributeName="r" values="50;70;50" dur="2s" repeatCount="indefinite"/>"#.to_string(),
            Motion::Orbit => format!(
                r#"<animateTransform attributeName="transform" type="translate" values="0,0; 20,0; 0,0; -20,0; 0,0" dur="2s" repeatCount="indefinite"/>"#
            ),
            Motion::Breathe => r#"<animate attributeName="opacity" values="0.5;1;0.5" dur="2.5s" repeatCount="indefinite"/>"#.to_string(),
            Motion::Glitch => r#"<animate attributeName="x" values="0;2;-2;1;0" dur="0.1s" repeatCount="indefinite"/>"#.to_string(),
            Motion::Flow => r#"<animate attributeName="stroke-dashoffset" from="0" to="100" dur="1.5s" repeatCount="indefinite"/>"#.to_string(),
        }
    }

    fn hexagon_points(&self, size: f32) -> String {
        (0..6)
            .map(|i| {
                let angle = std::f32::consts::PI / 3.0_f32 * i as f32 - std::f32::consts::PI / 6.0_f32;
                format!("{:.1},{:.1}", size * angle.cos(), size * angle.sin())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn triangle_points(&self, size: f32) -> String {
        (0..3)
            .map(|i| {
                let angle = std::f32::consts::PI * 2.0_f32 / 3.0_f32 * i as f32 - std::f32::consts::PI / 2.0_f32;
                format!("{:.1},{:.1}", size * angle.cos(), size * angle.sin())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn star_points(&self, size: f32, points: usize) -> String {
        let inner = size * 0.4_f32;
        (0..points * 2)
            .map(|i| {
                let angle = std::f32::consts::PI / points as f32 * i as f32 - std::f32::consts::PI / 2.0_f32;
                let r = if i % 2 == 0 { size } else { inner };
                format!("{:.1},{:.1}", r * angle.cos(), r * angle.sin())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Generate decoy patterns that are visually similar but distinct
    pub fn generate_decoys(&self, real: &Pattern, count: usize) -> Vec<String> {
        use gently_core::PatternEncoder;

        PatternEncoder::generate_decoys(real, count)
            .iter()
            .map(|p| self.render_svg(p))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gently_core::PatternEncoder;

    #[test]
    fn test_render_svg() {
        let engine = VisualEngine::new(400, 400);
        let hash = [42u8; 32];
        let pattern = PatternEncoder::encode(&hash);

        let svg = engine.render_svg(&pattern);

        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("viewBox"));
    }

    #[test]
    fn test_different_patterns_different_svg() {
        let engine = VisualEngine::new(400, 400);

        let pattern1 = PatternEncoder::encode(&[1u8; 32]);
        let pattern2 = PatternEncoder::encode(&[2u8; 32]);

        let svg1 = engine.render_svg(&pattern1);
        let svg2 = engine.render_svg(&pattern2);

        // Different patterns should produce different SVGs
        assert_ne!(svg1, svg2);
    }

    #[test]
    fn test_generate_decoys() {
        let engine = VisualEngine::new(400, 400);
        let pattern = PatternEncoder::encode(&[42u8; 32]);

        let decoys = engine.generate_decoys(&pattern, 3);

        assert_eq!(decoys.len(), 3);
        for decoy in &decoys {
            assert!(decoy.contains("<svg"));
        }
    }
}
