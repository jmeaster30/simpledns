use std::time::Duration;

use ratatui::{buffer::Buffer, crossterm::event::KeyCode, layout::{Constraint, Rect}, text::{Line, Text}, widgets::{Block, Paragraph, Row, Table, Widget}};
use ratatui::prelude::Stylize;
use ratatui::prelude::Style;

use crate::{settings::DnsSettings, simple_database::SimpleDatabase};

use super::{event::{SimpleEvent, SimpleEventResult}, view::View};

pub struct CacheListView { 
  simple_database: SimpleDatabase
}

impl CacheListView { 
  pub fn new(settings: &DnsSettings) -> Self {
    Self {
      simple_database: SimpleDatabase::new(settings.database_file.clone())
    }
  }

  pub fn new_boxed(settings: &DnsSettings) -> Box<Self> {
    Box::new(Self::new(settings))
  }
}

impl View for CacheListView {
  fn draw(&self, block: Block, area: Rect, buf: &mut Buffer) {
    match self.simple_database.get_all_cached_records() {
      Ok(records) => {
        Table::default()
          .rows(records.iter().collect::<Vec<Row<'_>>>())
          .header(Row::new(vec!["Query Type", "Domain", "Host/IP", "Expires In", "Priority", "Class"]).underlined().cyan())
          .widths([
            Constraint::Length(12),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(7)
          ])
          .row_highlight_style(Style::new().underlined())
          .highlight_symbol("->")
          .block(block)
          .render(area, buf); 
      }
      Err(err) => {
        let text = vec![
          "ERROR GETTING LIST OF CACHED RECORDS FROM DB".into(),
          err.to_string().into()
        ];
        Paragraph::new(text)
          .centered()
          .red()
          .bold()
          .italic()
          .block(block)
          .render(area, buf);
      }
    }
  }

  fn handle_event(&mut self, _: SimpleEvent) -> SimpleEventResult {
    SimpleEventResult::Bubble
  }

  fn open_view_control(&self) -> KeyCode {
    KeyCode::Char('c')
  }

  fn name(&self) -> Line {
    Line::from(vec![
      " ".into(),
      "C".red().bold(),
      "ached Records".blue(),
      " ".into()
    ])
  }

  fn help(&self) -> Text {
    Text::from(vec![
      "[ESC] - Exit SimpleDNS".into()
    ])
  }
  
  fn poll_rate(&self) -> Duration {
    Duration::from_secs(1)
  }
}
