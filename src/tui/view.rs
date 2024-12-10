use std::time::Duration;

use ratatui::{buffer::Buffer, crossterm::event::KeyCode, layout::Rect, text::{Line, Text}, widgets::{Block, Widget}};

use super::event::{SimpleEvent, SimpleEventResult};

pub trait View {
  fn draw(&self, block: Block, area: Rect, buf: &mut Buffer);
  fn handle_event(&mut self, event: SimpleEvent) -> SimpleEventResult;
  fn open_view_control(&self) -> KeyCode;
  fn name(&self) -> Line;
  fn help(&self) -> Text;
  fn poll_rate(&self) -> Duration;
}