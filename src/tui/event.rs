use ratatui::crossterm::event::{KeyEvent, MouseEvent};

pub enum SimpleEvent {
  Key(KeyEvent),
  Mouse(MouseEvent),
  Tick,
}

pub enum SimpleEventResult {
  Consume,
  Bubble
}