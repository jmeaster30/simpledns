use std::time::Duration;

use ratatui::{buffer::Buffer, crossterm::event::KeyCode, layout::Rect, text::{Line, Text}, widgets::{Block, Chart, Dataset, Paragraph, Row, Table, Widget}};
use ratatui::prelude::Stylize;
use ratatui::prelude::Style;

use crate::{dns_packet::DnsRecord, settings::DnsSettings, simple_database::SimpleDatabase};

use super::{event::{SimpleEvent, SimpleEventResult}, view::View};

pub struct RecordListView { 
  simple_database: SimpleDatabase
}

impl RecordListView { 
  pub fn new(settings: &DnsSettings) -> Self {
    Self {
      simple_database: SimpleDatabase::new(settings.database_file.clone())
    }
  }

  pub fn new_boxed(settings: &DnsSettings) -> Box<Self> {
    Box::new(Self::new(settings))
  }
}

impl View for RecordListView {
  fn draw(&self, block: Block, area: Rect, buf: &mut Buffer) {
    match self.simple_database.get_all_records() {
      Ok(records) => {
        Table::default()
          .rows(records.iter().collect::<Vec<Row<'_>>>()) // TODO There has to be a better way
          .header(Row::new(vec!["Query Type", "Domain", "Host/IP", "Priority", "TTL", "Class"]).underlined().cyan())
          .row_highlight_style(Style::new().underlined())
          .highlight_symbol("->")
          .block(block)
          .render(area, buf); 
      }
      Err(error) => {
        Paragraph::new("ERROR GETTING LIST OF RECORDS FROM DB")
          .centered()
          .red()
          .bold()
          .italic()
          .block(block)
          .render(area, buf);
      }
    }
    
  }

  fn handle_event(&mut self, event: SimpleEvent) -> SimpleEventResult {
    SimpleEventResult::Bubble
  }

  fn open_view_control(&self) -> KeyCode {
    KeyCode::Char('r')
  }

  fn name(&self) -> Line {
    Line::from(vec![
      " ".into(),
      "R".red().bold(),
      "ecords".blue(),
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
