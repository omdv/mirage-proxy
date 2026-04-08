use crate::vault::Vault;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::path::PathBuf;

pub struct VaultViewer {
    vault: Vault,
    sessions: Vec<String>,
    session_state: ListState,
    mappings: Vec<MappingDisplay>,
    table_state: TableState,
    search_query: String,
    input_mode: InputMode,
    status_message: String,
    view_mode: ViewMode,
}

#[derive(Clone)]
struct MappingDisplay {
    session_id: String,
    original: String,
    fake: String,
    kind: String,
    use_count: u64,
    last_used: String,
}

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Search,
}

#[derive(PartialEq)]
enum ViewMode {
    Sessions,
    Mappings,
}

impl VaultViewer {
    pub fn new(vault_path: PathBuf, key: &[u8; 32]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let vault = Vault::new_with_legacy(vault_path, key, None, 0);
        let sessions = vault.list_sessions();
        let mut session_state = ListState::default();
        if !sessions.is_empty() {
            session_state.select(Some(0));
        }

        let mut viewer = Self {
            vault,
            sessions,
            session_state,
            mappings: Vec::new(),
            table_state: TableState::default(),
            search_query: String::new(),
            input_mode: InputMode::Normal,
            status_message: "Press 'q' to quit, '/' to search, Tab to switch views, Enter to view session mappings".to_string(),
            view_mode: ViewMode::Sessions,
        };

        viewer.load_selected_session_mappings();
        Ok(viewer)
    }

    fn load_all_mappings(&mut self) {
        self.mappings.clear();
        
        for session_id in &self.sessions {
            if let Some(entries) = self.vault.get_session_mappings_full(session_id) {
                for (original, entry) in entries {
                    self.mappings.push(MappingDisplay {
                        session_id: session_id.clone(),
                        original: original.clone(),
                        fake: entry.fake.clone(),
                        kind: entry.kind.clone(),
                        use_count: entry.use_count,
                        last_used: entry.last_used.split('T').nth(1).unwrap_or(&entry.last_used).to_string(),
                    });
                }
            }
        }

        if !self.mappings.is_empty() {
            self.table_state.select(Some(0));
        }
    }

    fn load_selected_session_mappings(&mut self) {
        self.mappings.clear();

        if let Some(selected) = self.session_state.selected() {
            if let Some(session_id) = self.sessions.get(selected) {
                if let Some(entries) = self.vault.get_session_mappings_full(session_id) {
                    for (original, entry) in entries {
                        self.mappings.push(MappingDisplay {
                            session_id: session_id.clone(),
                            original: original.clone(),
                            fake: entry.fake.clone(),
                            kind: entry.kind.clone(),
                            use_count: entry.use_count,
                            last_used: entry.last_used.split('T').nth(1).unwrap_or(&entry.last_used).to_string(),
                        });
                    }
                }
            }
        }

        if !self.mappings.is_empty() {
            self.table_state.select(Some(0));
        } else {
            self.table_state.select(None);
        }
    }

    fn load_session_mappings(&mut self) {
        self.load_selected_session_mappings();
        self.view_mode = ViewMode::Mappings;
        self.status_message = if let Some(selected) = self.session_state.selected() {
            if let Some(session_id) = self.sessions.get(selected) {
                format!("Viewing session: {} ({} mappings)", session_id, self.mappings.len())
            } else {
                "No session selected".to_string()
            }
        } else {
            "No session selected".to_string()
        };
    }

    fn apply_search(&mut self) {
        if self.search_query.is_empty() {
            self.load_all_mappings();
            return;
        }

        let query = self.search_query.to_lowercase();
        self.mappings.retain(|m| {
            m.original.to_lowercase().contains(&query)
                || m.fake.to_lowercase().contains(&query)
                || m.kind.to_lowercase().contains(&query)
                || m.session_id.to_lowercase().contains(&query)
        });

        if !self.mappings.is_empty() {
            self.table_state.select(Some(0));
        }
    }

    fn next_session(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let i = match self.session_state.selected() {
            Some(i) => {
                if i >= self.sessions.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.session_state.select(Some(i));
        self.load_selected_session_mappings();
    }

    fn previous_session(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let i = match self.session_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.sessions.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.session_state.select(Some(i));
        self.load_selected_session_mappings();
    }

    fn next_mapping(&mut self) {
        if self.mappings.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.mappings.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous_mapping(&mut self) {
        if self.mappings.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.mappings.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn render_sessions(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .sessions
            .iter()
            .map(|s| {
                let count = self.vault.get_session_mappings_full(s).map(|m| m.len()).unwrap_or(0);
                ListItem::new(format!("{} ({} mappings)", s, count))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Sessions ({}) ", self.sessions.len()))
            )
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol("→ ");

        f.render_stateful_widget(list, area, &mut self.session_state);
    }

    fn render_mappings(&mut self, f: &mut Frame, area: Rect) {
        let header_cells = ["Session", "Original", "Fake", "Kind", "Uses", "Last Used"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        let header = Row::new(header_cells).height(1).bottom_margin(1);

        let rows = self.mappings.iter().map(|m| {
            let cells = vec![
                Cell::from(m.session_id.chars().take(8).collect::<String>()),
                Cell::from(m.original.as_str()),
                Cell::from(m.fake.as_str()),
                Cell::from(m.kind.as_str()),
                Cell::from(m.use_count.to_string()),
                Cell::from(m.last_used.split('.').next().unwrap_or(&m.last_used)),
            ];
            Row::new(cells).height(1)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Min(20),
                Constraint::Min(20),
                Constraint::Length(15),
                Constraint::Length(6),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Mappings ({}) ", self.mappings.len()))
        )
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("→ ");

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_detail(&self, f: &mut Frame, area: Rect) {
        let detail_text = match self.view_mode {
            ViewMode::Sessions => {
                if let Some(selected) = self.session_state.selected() {
                    if let Some(session_id) = self.sessions.get(selected) {
                        let count = self.vault.get_session_mappings_full(session_id).map(|m| m.len()).unwrap_or(0);
                        Paragraph::new(vec![
                            Line::from(vec![
                                Span::styled("Session ID: ", Style::default().fg(Color::Cyan)),
                                Span::raw(session_id),
                            ]),
                            Line::from(vec![
                                Span::styled("Mappings: ", Style::default().fg(Color::Cyan)),
                                Span::raw(count.to_string()),
                            ]),
                            Line::from(""),
                            Line::from("Press Enter to view mappings"),
                        ])
                    } else {
                        Paragraph::new("No session selected")
                    }
                } else {
                    Paragraph::new("No session selected")
                }
            }
            ViewMode::Mappings => {
                if let Some(selected) = self.table_state.selected() {
                    if let Some(mapping) = self.mappings.get(selected) {
                        Paragraph::new(vec![
                            Line::from(vec![
                                Span::styled("Session: ", Style::default().fg(Color::Cyan)),
                                Span::raw(&mapping.session_id),
                            ]),
                            Line::from(vec![
                                Span::styled("Original: ", Style::default().fg(Color::Cyan)),
                                Span::raw(&mapping.original),
                            ]),
                            Line::from(vec![
                                Span::styled("Fake: ", Style::default().fg(Color::Cyan)),
                                Span::raw(&mapping.fake),
                            ]),
                            Line::from(vec![
                                Span::styled("Kind: ", Style::default().fg(Color::Cyan)),
                                Span::raw(&mapping.kind),
                            ]),
                            Line::from(vec![
                                Span::styled("Use Count: ", Style::default().fg(Color::Cyan)),
                                Span::raw(mapping.use_count.to_string()),
                            ]),
                            Line::from(vec![
                                Span::styled("Last Used: ", Style::default().fg(Color::Cyan)),
                                Span::raw(&mapping.last_used),
                            ]),
                        ])
                    } else {
                        Paragraph::new("No mapping selected")
                    }
                } else {
                    Paragraph::new("No mapping selected")
                }
            }
        };

        f.render_widget(
            detail_text.block(Block::default().borders(Borders::ALL).title(" Details ")),
            area,
        );
    }

    fn render_input(&self, f: &mut Frame, area: Rect) {
        let (title, content) = match self.input_mode {
            InputMode::Search => (" Search ", &self.search_query),
            InputMode::Normal => (" Status ", &self.status_message),
        };

        let input = Paragraph::new(content.as_str())
            .style(Style::default().fg(if self.input_mode == InputMode::Normal {
                Color::White
            } else {
                Color::Yellow
            }))
            .block(Block::default().borders(Borders::ALL).title(title));

        f.render_widget(input, area);
    }

    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.run_app(&mut terminal);

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    fn run_app(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            terminal.draw(|f| self.ui(f))?;

            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match self.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => {
                            match self.view_mode {
                                ViewMode::Sessions => self.next_session(),
                                ViewMode::Mappings => self.next_mapping(),
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            match self.view_mode {
                                ViewMode::Sessions => self.previous_session(),
                                ViewMode::Mappings => self.previous_mapping(),
                            }
                        }
                        KeyCode::Tab => {
                            self.view_mode = match self.view_mode {
                                ViewMode::Sessions => ViewMode::Mappings,
                                ViewMode::Mappings => ViewMode::Sessions,
                            };
                            if self.view_mode == ViewMode::Sessions {
                                self.load_selected_session_mappings();
                            }
                            self.status_message = format!("Switched to {} view", 
                                if self.view_mode == ViewMode::Sessions { "sessions" } else { "mappings" });
                        }
                        KeyCode::Enter => {
                            if self.view_mode == ViewMode::Sessions {
                                self.load_session_mappings();
                            }
                        }
                        KeyCode::Char('/') => {
                            self.input_mode = InputMode::Search;
                            self.search_query.clear();
                        }
                        KeyCode::Char('b') => {
                            if self.view_mode == ViewMode::Mappings {
                                self.view_mode = ViewMode::Sessions;
                                self.load_selected_session_mappings();
                                self.status_message = "Back to sessions view".to_string();
                            }
                        }
                        _ => {}
                    },
                    InputMode::Search => match key.code {
                        KeyCode::Enter => {
                            self.apply_search();
                            self.input_mode = InputMode::Normal;
                            self.status_message = format!("Found {} mappings", self.mappings.len());
                        }
                        KeyCode::Char(c) => {
                            self.search_query.push(c);
                        }
                        KeyCode::Backspace => {
                            self.search_query.pop();
                        }
                        KeyCode::Esc => {
                            self.input_mode = InputMode::Normal;
                            self.search_query.clear();
                            self.load_all_mappings();
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    fn ui(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(8),
                Constraint::Length(3),
            ])
            .split(f.size());

        match self.view_mode {
            ViewMode::Sessions => {
                let h_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                    .split(chunks[0]);
                
                self.render_sessions(f, h_chunks[0]);
                self.render_mappings(f, h_chunks[1]);
            }
            ViewMode::Mappings => {
                self.render_mappings(f, chunks[0]);
            }
        }

        self.render_detail(f, chunks[1]);
        self.render_input(f, chunks[2]);
    }
}
