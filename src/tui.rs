use std::{collections::HashMap, io};

use crossterm::event::{self, Event, KeyCode};
use ratatui::{prelude::*, widgets::*};
use thiserror::Error;

use crate::filters::{load_abstract_groups, AbstractGroupDef, GroupRule, ProfileError};

#[derive(Error, Debug)]
pub enum TuiError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Profile error: {0}")]
    Profile(#[from] ProfileError),
}

type Result<T> = std::result::Result<T, TuiError>;

struct App {
    rules: Vec<(String, AbstractGroupDef)>,
    list_state: ListState,
}

impl App {
    fn new(rules: HashMap<String, AbstractGroupDef>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            rules: rules.into_iter().collect(),
            list_state,
        }
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.rules.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.rules.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }
}

pub fn run_tui() -> Result<()> {
    // Initialize the terminal
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let rules = load_abstract_groups()?;
    let mut app = App::new(rules);

    let result = std::panic::catch_unwind(move || loop {
        terminal.draw(|f| view(&mut app, f)).unwrap();

        if let Event::Key(key) = event::read().unwrap() {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.previous(),
                _ => {}
            }
        }
    });

    ratatui::restore();

    if let Err(err) = result {
        eprintln!("TUI panicked: {:?}", err);
    }

    Ok(())
}

fn view(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(f.area());

    let items: Vec<ListItem> = app
        .rules
        .iter()
        .map(|(name, _)| ListItem::new(name.as_str()))
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Abstract Rules")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, chunks[0], &mut app.list_state);

    if let Some(selected) = app.list_state.selected() {
        let (name, rule) = &app.rules[selected];
        let rules_text = rule
            .rules
            .iter()
            .map(|r| match r {
                GroupRule::Syscall(s) => {
                    let mut text = format!("  - Syscall: {}", s.name);
                    if !s.conditions.is_empty() {
                        text.push_str("\n    Conditions:\n");
                        for c in &s.conditions {
                            text.push_str(&format!("      - {:?}\n", c));
                        }
                    }
                    text
                }
                GroupRule::GroupRef(g) => format!("  - Group: {}", g.group),
            })
            .collect::<Vec<_>>()
            .join("\n");

        let text = format!("Name: {}\n\nRules:\n{}", name, rules_text);
        let paragraph =
            Paragraph::new(text).block(Block::default().title("Details").borders(Borders::ALL));
        f.render_widget(paragraph, chunks[1]);
    }
}

