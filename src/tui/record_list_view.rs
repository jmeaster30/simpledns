use ratatui::{buffer::Buffer, layout::Rect, text::{Line, Span, Text}};
use crate::{settings::DnsSettings, tui::ratatui::prelude::Stylize};

use super::{event::{SimpleEvent, SimpleEventResult}, view::View};

pub struct RecordListView { 

}

impl RecordListView { 
  pub fn new(settings: &DnsSettings) -> Self {
    Self {}
  }

  pub fn new_boxed(settings: &DnsSettings) -> Box<Self> {
    Box::new(Self::new(settings))
  }
}

impl View for RecordListView {
  fn draw(&self, area: Rect, buf: &mut Buffer) {
    todo!()
  }

  fn handle_event(&mut self, event: SimpleEvent) -> SimpleEventResult {
    todo!()
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
      "This is a test".into(),
      "of the help window".into()
    ])
  }
}