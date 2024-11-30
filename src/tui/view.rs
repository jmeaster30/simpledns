use ratatui::{buffer::Buffer, layout::Rect, text::{Line, Text}};

use super::event::{SimpleEvent, SimpleEventResult};

pub trait View {
  fn draw(&self, area: Rect, buf: &mut Buffer);
  fn handle_event(&mut self, event: SimpleEvent) -> SimpleEventResult;
  fn name(&self) -> Line;
  fn help(&self) -> Text;
}