use crate::audit::AuditEntry;
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
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub struct AuditViewer {
    entries: Vec<AuditEntry>,
    filtered_indices: Vec<usize>,
    table_state: TableState,
    scroll_offset: usize,
    filter_action: Option<String>,
    filter_kind: Option<String>,
    search_query: String,
    input_mode: InputMode,
    status_message: String,
}

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Search,
    FilterAction,
    FilterKind,
}

impl AuditViewer {
    pub fn new(audit_path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let entries = Self::load_entries(&audit_path)?;
        let filtered_indices = (0..entries.len()).collect();
        
        Ok(Self {
            entries,
            filtered_indices,
            table_state: TableState::default(),
            scroll_offset: 0,
            filter_action: None,
            filter_kind: None,
            search_query: String::new(),
            input_mode: InputMode::Normal,
            status_message: "Press 'q' to quit, '/' to search, 'a' to filter by action, 'k' to filter by kind, 'c' to clear filters".to_string(),
        })
    }

    fn load_entries(path: &PathBuf) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn apply_filters(&mut self) {
        self.filtered_indices = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                let action_match = self
                    .filter_action
                    .as_ref()
                    .map(|f| entry.action.to_lowercase().contains(&f.to_lowercase()))
                    .unwrap_or(true);

                let kind_match = self
                    .filter_kind
                    .as_ref()
                    .map(|f| entry.kind.to_lowercase().contains(&f.to_lowercase()))
                    .unwrap_or(true);

                let search_match = if self.search_query.is_empty() {
                    true
                } else {
                    let query = self.search_query.to_lowercase();
                    entry.kind.to_lowercase().contains(&query)
                        || entry.action.to_lowercase().contains(&query)
                        || entry.context_snippet.to_lowercase().contains(&query)
                        || entry
                            .original
                            .as_ref()
                            .map(|o| o.to_lowercase().contains(&query))
                            .unwrap_or(false)
                };

                action_match && kind_match && search_match
            })
            .map(|(idx, _)| idx)
            .collect();

        self.scroll_offset = 0;
        self.table_state.select(if self.filtered_indices.is_empty() {
            None
        } else {
            Some(0)
        });
    }

    fn next(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_indices.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_indices.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn render_table(&mut self, f: &mut Frame, area: Rect) {
        let header_cells = ["Time", "Kind", "Action", "Confidence", "Context"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        let header = Row::new(header_cells).height(1).bottom_margin(1);

        let rows = self.filtered_indices.iter().map(|&idx| {
            let entry = &self.entries[idx];
            let time = entry.timestamp.split('T').nth(1).unwrap_or(&entry.timestamp);
            let time = time.split('.').next().unwrap_or(time);
            
            let action_color = match entry.action.as_str() {
                "redacted" => Color::Red,
                "masked" => Color::Yellow,
                "warned" => Color::Magenta,
                _ => Color::Gray,
            };

            let cells = vec![
                Cell::from(time),
                Cell::from(entry.kind.as_str()),
                Cell::from(entry.action.as_str()).style(Style::default().fg(action_color)),
                Cell::from(format!("{:.2}", entry.confidence)),
                Cell::from(entry.context_snippet.as_str()),
            ];
            Row::new(cells).height(1)
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Min(30),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Audit Log ({} entries) ", self.filtered_indices.len()))
        )
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("→ ");

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_detail(&self, f: &mut Frame, area: Rect) {
        let detail_text = if let Some(selected) = self.table_state.selected() {
            if let Some(&idx) = self.filtered_indices.get(selected) {
                let entry = &self.entries[idx];
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("Timestamp: ", Style::default().fg(Color::Cyan)),
                        Span::raw(&entry.timestamp),
                    ]),
                    Line::from(vec![
                        Span::styled("Kind: ", Style::default().fg(Color::Cyan)),
                        Span::raw(&entry.kind),
                    ]),
                    Line::from(vec![
                        Span::styled("Action: ", Style::default().fg(Color::Cyan)),
                        Span::raw(&entry.action),
                    ]),
                    Line::from(vec![
                        Span::styled("Confidence: ", Style::default().fg(Color::Cyan)),
                        Span::raw(format!("{:.2}", entry.confidence)),
                    ]),
                ];

                if let Some(ref hash) = entry.value_hash {
                    lines.push(Line::from(vec![
                        Span::styled("Value Hash: ", Style::default().fg(Color::Cyan)),
                        Span::raw(hash),
                    ]));
                }

                if let Some(ref original) = entry.original {
                    lines.push(Line::from(vec![
                        Span::styled("Original: ", Style::default().fg(Color::Cyan)),
                        Span::raw(original),
                    ]));
                }

                lines.push(Line::from(vec![
                    Span::styled("Context: ", Style::default().fg(Color::Cyan)),
                    Span::raw(&entry.context_snippet),
                ]));

                Paragraph::new(lines)
            } else {
                Paragraph::new("No entry selected")
            }
        } else {
            Paragraph::new("No entry selected")
        };

        f.render_widget(
            detail_text.block(Block::default().borders(Borders::ALL).title(" Details ")),
            area,
        );
    }

    fn render_input(&self, f: &mut Frame, area: Rect) {
        let (title, content) = match self.input_mode {
            InputMode::Search => (" Search ", &self.search_query),
            InputMode::FilterAction => (" Filter by Action ", &self.search_query),
            InputMode::FilterKind => (" Filter by Kind ", &self.search_query),
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
                        KeyCode::Down | KeyCode::Char('j') => self.next(),
                        KeyCode::Up | KeyCode::Char('k') => self.previous(),
                        KeyCode::Char('/') => {
                            self.input_mode = InputMode::Search;
                            self.search_query.clear();
                        }
                        KeyCode::Char('a') => {
                            self.input_mode = InputMode::FilterAction;
                            self.search_query.clear();
                        }
                        KeyCode::Char('t') => {
                            self.input_mode = InputMode::FilterKind;
                            self.search_query.clear();
                        }
                        KeyCode::Char('c') => {
                            self.filter_action = None;
                            self.filter_kind = None;
                            self.search_query.clear();
                            self.apply_filters();
                            self.status_message = "Filters cleared".to_string();
                        }
                        _ => {}
                    },
                    _ => match key.code {
                        KeyCode::Enter => {
                            match self.input_mode {
                                InputMode::Search => {
                                    self.apply_filters();
                                    self.status_message = format!("Searching for: {}", self.search_query);
                                }
                                InputMode::FilterAction => {
                                    self.filter_action = if self.search_query.is_empty() {
                                        None
                                    } else {
                                        Some(self.search_query.clone())
                                    };
                                    self.apply_filters();
                                    self.status_message = format!("Filter action: {:?}", self.filter_action);
                                }
                                InputMode::FilterKind => {
                                    self.filter_kind = if self.search_query.is_empty() {
                                        None
                                    } else {
                                        Some(self.search_query.clone())
                                    };
                                    self.apply_filters();
                                    self.status_message = format!("Filter kind: {:?}", self.filter_kind);
                                }
                                _ => {}
                            }
                            self.input_mode = InputMode::Normal;
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
                Constraint::Length(10),
                Constraint::Length(3),
            ])
            .split(f.size());

        self.render_table(f, chunks[0]);
        self.render_detail(f, chunks[1]);
        self.render_input(f, chunks[2]);
    }
}
