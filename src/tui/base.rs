use std::borrow::Borrow;
use std::io::Result;
use std::thread::current;

use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, MouseEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::style::Style;
use ratatui::symbols::border;
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListDirection, ListState, Paragraph, StatefulWidget, Widget};
use ratatui::{DefaultTerminal, Frame};

use crate::settings::DnsSettings;
use crate::log_debug;
use crate::simple_database::SimpleDatabase;

use super::event::{SimpleEvent, SimpleEventResult};
use super::record_list_view::RecordListView;
use super::view::View;

pub fn tui_start(settings: &DnsSettings) -> Result<()> {
  log_debug!("Starting TUI....");
  let mut terminal = ratatui::init();
  terminal.clear().expect("Couldn't clear terminal :(");
  let mut state = AppState::new();
  App::new(settings).run(&mut terminal, &mut state)?;
  ratatui::restore();
  Ok(())
}

struct AppState {
  selected_view: ListState,
}

impl AppState {
  pub fn new() -> Self {
    Self {
      selected_view: ListState::default().with_selected(Some(0)),
    }
  }

  pub fn current_view(&self) -> usize {
    match self.selected_view.selected() {
      Some(idx) => idx,
      None => panic!("idk what to do here")
    }
  }
}

struct App {
  //simple_connection: SimpleDatabase,
  views: Vec<Box<dyn View>>,
  exit: bool
}

impl App {
  pub fn new(settings: &DnsSettings) -> Self {
    Self {
      //simple_connection: SimpleDatabase::new(settings.database_file.clone()),
      views: vec![RecordListView::new_boxed(settings)],
      exit: false
    }
  }

  pub fn run(&mut self, terminal: &mut DefaultTerminal, state: &mut AppState) -> Result<()> {
    while !self.exit {
      terminal.draw(|frame| self.draw(frame, state))?;
      self.handle_events(state)?;
    }
    Ok(())
  }

  pub fn draw(&self, frame: &mut Frame, state: &mut AppState) {
    frame.render_stateful_widget(self, frame.area(), state);
  }

  pub fn handle_events(&mut self, state: &AppState) -> Result<()> {
    let mut current_view = &mut self.views[state.current_view()];
    match event::poll(current_view.poll_rate()) {
      Ok(true) => {
        let simple_event: SimpleEvent = event::read()?.into();
        match current_view.handle_event(simple_event.clone()) {
          SimpleEventResult::Consume => {}
          SimpleEventResult::Bubble => match simple_event {
            SimpleEvent::Key(key) if key.kind == KeyEventKind::Press && key.code == KeyCode::Esc => {
              self.exit = true;
            }
            _ => {}
          }
        }
      }
      Ok(false) => { current_view.handle_event(SimpleEvent::Tick); }
      Err(error) => {} // WHAT TO DO???
    }
    Ok(())
  }
}

impl StatefulWidget for &App {
  type State = AppState;

  fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
    let current_view = &self.views[state.current_view()];

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

    current_view.draw(block, main_area, buf);

    let views = self.views.iter().map(|x| x.name()).collect::<Vec<Line>>();
    let view_title = Line::from("[ Views ]".bold());
    let views_block = Block::bordered()
      .title(view_title.centered())
      .border_set(border::DOUBLE);
    StatefulWidget::render(List::new(views)
      .highlight_style(Style::new().bold().italic())
      .highlight_symbol("->")
      .direction(ListDirection::TopToBottom)
      .block(views_block), views_area, buf, &mut state.selected_view);

    let help = current_view.help();
    let help_title = Line::from("[ Help ]".bold());
    let help_block = Block::bordered()
      .title(help_title.centered())
      .border_set(border::DOUBLE);
    Paragraph::new(help)
      .block(help_block)
      .render(help_area, buf);
  }
}
