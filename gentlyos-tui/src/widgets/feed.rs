//! Living Feed widget
//!
//! Displays auto-updating feed items with temperature indicators.

use crate::app::{FeedItem, Temperature};
use crate::theme::ThemePalette;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, StatefulWidget, Widget},
};

/// State for the feed widget
#[derive(Debug, Default)]
pub struct FeedWidgetState {
    pub scroll: usize,
    pub selected: Option<usize>,
}

impl FeedWidgetState {
    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }
}

/// Living feed widget
pub struct FeedWidget<'a> {
    items: &'a [FeedItem],
    palette: &'a ThemePalette,
    active: bool,
}

impl<'a> FeedWidget<'a> {
    pub fn new(items: &'a [FeedItem], palette: &'a ThemePalette, active: bool) -> Self {
        Self {
            items,
            palette,
            active,
        }
    }

    fn temperature_style(&self, temp: &Temperature) -> Style {
        match temp {
            Temperature::Hot => self.palette.hot_style(),
            Temperature::Warm => self.palette.warm_style(),
            Temperature::Cool => self.palette.cool_style(),
            Temperature::Cold => self.palette.cold_style(),
        }
    }

    fn render_item(&self, item: &FeedItem, selected: bool, width: usize) -> ListItem<'a> {
        let temp_style = self.temperature_style(&item.temperature);
        let time = item.timestamp.format("%H:%M").to_string();

        // Calculate available width for title
        let prefix_len = 5; // "🔥 " + padding
        let time_len = 7;   // " HH:MM "
        let source_len = 12; // " [Source] "
        let title_max = width.saturating_sub(prefix_len + time_len + source_len);

        let title = if item.title.len() > title_max {
            format!("{}...", &item.title[..title_max.saturating_sub(3)])
        } else {
            format!("{:<width$}", item.title, width = title_max)
        };

        let style = if selected {
            self.palette.selection_style()
        } else {
            temp_style
        };

        let line = Line::from(vec![
            Span::styled(
                format!("{} ", item.temperature.icon()),
                temp_style,
            ),
            Span::styled(title, style),
            Span::styled(
                format!(" {} ", time),
                Style::default()
                    .fg(self.palette.text_muted)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(
                format!("[{}]", truncate_str(&item.source, 8)),
                Style::default().fg(self.palette.text_secondary),
            ),
        ]);

        ListItem::new(line)
    }
}

impl<'a> StatefulWidget for FeedWidget<'a> {
    type State = FeedWidgetState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .skip(state.scroll)
            .take(area.height as usize)
            .map(|(idx, item)| {
                let selected = state.selected == Some(idx);
                self.render_item(item, selected, area.width as usize)
            })
            .collect();

        let list = List::new(items);
        Widget::render(list, area, buf);
    }
}

/// Compact feed item for sidebar
pub struct CompactFeedItem<'a> {
    item: &'a FeedItem,
    palette: &'a ThemePalette,
    selected: bool,
}

impl<'a> CompactFeedItem<'a> {
    pub fn new(item: &'a FeedItem, palette: &'a ThemePalette, selected: bool) -> Self {
        Self {
            item,
            palette,
            selected,
        }
    }
}

impl<'a> Widget for CompactFeedItem<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let temp_style = match self.item.temperature {
            Temperature::Hot => self.palette.hot_style(),
            Temperature::Warm => self.palette.warm_style(),
            Temperature::Cool => self.palette.cool_style(),
            Temperature::Cold => self.palette.cold_style(),
        };

        let style = if self.selected {
            self.palette.selection_style()
        } else {
            temp_style
        };

        let icon = self.item.temperature.icon();
        let title = truncate_str(&self.item.title, area.width as usize - 3);

        let text = format!("{} {}", icon, title);
        buf.set_string(area.x, area.y, &text, style);
    }
}

/// Feed summary widget showing counts by temperature
pub struct FeedSummary<'a> {
    items: &'a [FeedItem],
    palette: &'a ThemePalette,
}

impl<'a> FeedSummary<'a> {
    pub fn new(items: &'a [FeedItem], palette: &'a ThemePalette) -> Self {
        Self { items, palette }
    }

    fn count_by_temp(&self, temp: Temperature) -> usize {
        self.items.iter().filter(|i| i.temperature == temp).count()
    }
}

impl<'a> Widget for FeedSummary<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let hot = self.count_by_temp(Temperature::Hot);
        let warm = self.count_by_temp(Temperature::Warm);
        let cool = self.count_by_temp(Temperature::Cool);

        let y = area.y;
        let mut x = area.x;

        // Hot count
        buf.set_string(x, y, "🔥", self.palette.hot_style());
        x += 2;
        buf.set_string(x, y, &format!("{} ", hot), self.palette.hot_style());
        x += format!("{} ", hot).len() as u16;

        // Warm count
        buf.set_string(x, y, "🌡️", self.palette.warm_style());
        x += 2;
        buf.set_string(x, y, &format!("{} ", warm), self.palette.warm_style());
        x += format!("{} ", warm).len() as u16;

        // Cool count
        buf.set_string(x, y, "❄️", self.palette.cool_style());
        x += 2;
        buf.set_string(x, y, &format!("{}", cool), self.palette.cool_style());
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
