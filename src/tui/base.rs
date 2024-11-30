use std::io::Result;

use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::Rect;
use ratatui::prelude::Stylize;
use ratatui::symbols::border;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Widget};
use ratatui::{DefaultTerminal, Frame};

use crate::settings::DnsSettings;
use crate::log_info;
use crate::simple_database::SimpleDatabase;

pub fn tui_start(settings: &DnsSettings) -> Result<()> {
  log_info!("Starting TUI....");
  let mut terminal = ratatui::init();
  terminal.clear().expect("Couldn't clear terminal :(");
  App::new(settings).run(&mut terminal);
  ratatui::restore();
  Ok(())
}

struct App {
  simple_connection: SimpleDatabase,
  exit: bool
}

impl App {
  pub fn new(settings: &DnsSettings) -> Self {
    return Self {
      simple_connection: SimpleDatabase::new(settings.database_file.clone()),
      exit: false
    }
  }

  pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
    while !self.exit {
      terminal.draw(|frame| self.draw(frame))?;
      self.handle_events()?;
    }
    Ok(())
  }

  pub fn draw(&self, frame: &mut Frame) {
    frame.render_widget(self, frame.area());
  }

  pub fn handle_events(&mut self) -> Result<()> {
    if let Event::Key(key) = event::read()? {
      if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
        self.exit = true;
      }
    }
    Ok(())
  }
}

impl Widget for &App {
  fn render(self, area: Rect, buf: &mut Buffer) {
    let title = Line::from(" SimpleDNS ".bold());
    let block = Block::bordered()
      .title(title.centered())
      .border_set(border::THICK);

    Paragraph::new("TODO show the records")
      .centered()
      .block(block)
      .render(area, buf)
  }
}
