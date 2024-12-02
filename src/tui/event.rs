use ratatui::crossterm::event::{Event, KeyEvent, MouseEvent};

#[derive(Clone)]
pub enum SimpleEvent {
  Key(KeyEvent),
  Mouse(MouseEvent),
  Paste(String),
  Focus(bool),
  Resize(u16, u16),
  Tick,
}

impl From<Event> for SimpleEvent {
  fn from(value: Event) -> Self {
    match value {
      Event::FocusGained =>SimpleEvent::Focus(true),
      Event::FocusLost => SimpleEvent::Focus(false),
      Event::Key(key_event) => SimpleEvent::Key(key_event),
      Event::Mouse(mouse_event) => SimpleEvent::Mouse(mouse_event),
      Event::Paste(data) => SimpleEvent::Paste(data),
      Event::Resize(x, y) => SimpleEvent::Resize(x, y),
    }
  }
}

pub enum SimpleEventResult {
  Consume,
  Bubble
}