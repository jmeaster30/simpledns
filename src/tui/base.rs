use std::borrow::Borrow;
use std::io::Result;

use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, MouseEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::symbols::border;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Widget};
use ratatui::{DefaultTerminal, Frame};

use crate::settings::DnsSettings;
use crate::log_info;
use crate::simple_database::SimpleDatabase;

use super::record_list_view::RecordListView;
use super::view::View;

pub fn tui_start(settings: &DnsSettings) -> Result<()> {
  log_info!("Starting TUI....");
  let mut terminal = ratatui::init();
  terminal.clear().expect("Couldn't clear terminal :(");
  App::new(settings).run(&mut terminal);
  ratatui::restore();
  Ok(())
}

struct App {
  //simple_connection: SimpleDatabase,
  views: Vec<Box<dyn View>>,
  current_view: usize,
  exit: bool
}

impl App {
  pub fn new(settings: &DnsSettings) -> Self {
    Self {
      //simple_connection: SimpleDatabase::new(settings.database_file.clone()),
      views: vec![RecordListView::new_boxed(settings)],
      current_view: 0,
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
    let main_layout = Layout::default()
      .direction(Direction::Horizontal)
      .constraints(vec![
        Constraint::Percentage(80),
        Constraint::Percentage(20),
      ]).split(area);
    let main_area = main_layout[0];

    let side_layout = Layout::default()
      .direction(Direction::Vertical)
      .constraints(vec![
        Constraint::Percentage(50),
        Constraint::Percentage(50),
      ]).split(main_layout[1]);
    let views_area = side_layout[0];
    let help_area = side_layout[1];

    let title = Line::from("[ SimpleDNS ]".bold());

    let block = Block::bordered()
      .title(title.centered())
      .border_set(border::DOUBLE);

    Paragraph::new("TODO show the records")
      .centered()
      .block(block)
      .render(main_area, buf);

    let views = self.views.iter().map(|x| x.name()).collect::<Vec<Line>>();
    let view_title = Line::from("[ Views ]".bold());
    let views_block = Block::bordered()
      .title(view_title.centered())
      .border_set(border::DOUBLE);
    Paragraph::new(views)
      .block(views_block)
      .render(views_area, buf);

    let help = self.views[self.current_view].help();
    let help_title = Line::from("[ Help ]".bold());
    let help_block = Block::bordered()
      .title(help_title.centered())
      .border_set(border::DOUBLE);
    Paragraph::new(help)
      .block(help_block)
      .render(help_area, buf);
  }
}
