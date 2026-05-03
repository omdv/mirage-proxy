use crate::audit::{AuditEntry, AuditLog, AUDIT_KEY_LEN};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub struct AuditViewer {
    entries: Vec<AuditEntry>,
    filtered_indices: Vec<usize>,
    table_state: TableState,
    search_query: String,
    input_mode: InputMode,
    status_message: String,
    detail_scroll: u16,
    filter_mode: FilterMode,
}

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Search,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum FilterMode {
    All,
    ReplacedOnly,
}
impl AuditViewer {
    pub fn new(
        audit_path: PathBuf,
        decrypt_key: Option<[u8; AUDIT_KEY_LEN]>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let entries = Self::load_entries(&audit_path, decrypt_key.as_ref())?;
        let filtered_indices = (0..entries.len()).collect();

        let mut viewer = Self {
            entries,
            filtered_indices,
            table_state: TableState::default(),
            search_query: String::new(),
            input_mode: InputMode::Normal,
            status_message: "Press q quit, / search, j/k navigate, f filter".to_string(),
            detail_scroll: 0,
            filter_mode: FilterMode::All,
        };
        viewer.apply_filters();
        Ok(viewer)
    }

    fn load_entries(
        path: &PathBuf,
        decrypt_key: Option<&[u8; AUDIT_KEY_LEN]>,
    ) -> Result<Vec<AuditEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let json_line = if AuditLog::is_encrypted_line(line) {
                if let Some(key) = decrypt_key {
                    match AuditLog::decrypt_audit_line(line, key) {
                        Ok(v) => v,
                        Err(_) => continue,
                    }
                } else {
                    continue;
                }
            } else {
                line.to_string()
            };

            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&json_line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn apply_filters(&mut self) {
        let q = self.search_query.to_lowercase();
        self.filtered_indices = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if self.filter_mode == FilterMode::ReplacedOnly && !e.has_replacements {
                    return false;
                }
                if q.is_empty() {
                    return true;
                }
                e.local_url.to_lowercase().contains(&q)
                    || e.remote_url.to_lowercase().contains(&q)
                    || e.model
                        .as_ref()
                        .map(|v| v.to_lowercase().contains(&q))
                        .unwrap_or(false)
                    || e.replacements.iter().any(|r| {
                        r.original.to_lowercase().contains(&q)
                            || r.replaced.to_lowercase().contains(&q)
                    })
            })
            .map(|(i, _)| i)
            .collect();

        self.table_state.select(if self.filtered_indices.is_empty() {
            None
        } else {
            Some(0)
        });
        self.detail_scroll = 0;
    }

    fn next(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) if i < self.filtered_indices.len() - 1 => i + 1,
            _ => 0,
        };
        self.table_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn previous(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(0) | None => self.filtered_indices.len() - 1,
            Some(i) => i - 1,
        };
        self.table_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn toggle_filter_mode(&mut self) {
        self.filter_mode = match self.filter_mode {
            FilterMode::All => FilterMode::ReplacedOnly,
            FilterMode::ReplacedOnly => FilterMode::All,
        };
        let label = match self.filter_mode {
            FilterMode::All => "ALL",
            FilterMode::ReplacedOnly => "REPLACED only",
        };
        self.status_message = format!("Filter: {}", label);
        self.apply_filters();
    }

    fn render_table(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let header = Row::new(["Time", "Local URL", "Remote URL", "Model", "Replacements"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let rows = self.filtered_indices.iter().map(|&idx| {
            let e = &self.entries[idx];
            let time = e
                .timestamp
                .split('T')
                .nth(1)
                .unwrap_or(&e.timestamp)
                .split('.')
                .next()
                .unwrap_or(&e.timestamp)
                .to_string();
            Row::new(vec![
                Cell::from(time),
                Cell::from(e.local_url.clone()),
                Cell::from(e.remote_url.clone()),
                Cell::from(e.model.clone().unwrap_or_else(|| "-".to_string())),
                Cell::from(if e.has_replacements { "YES" } else { "NO" }),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Calls ({}) ", self.filtered_indices.len())),
        )
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("→ ");

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_detail(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let detail = if let Some(selected) = self.table_state.selected() {
            if let Some(&idx) = self.filtered_indices.get(selected) {
                let e = &self.entries[idx];
                if e.replacements.is_empty() {
                    Paragraph::new(vec![
                        Line::from(vec![
                            Span::styled("Local: ", Style::default().fg(Color::Cyan)),
                            Span::raw(&e.local_url),
                        ]),
                        Line::from(vec![
                            Span::styled("Remote: ", Style::default().fg(Color::Cyan)),
                            Span::raw(&e.remote_url),
                        ]),
                        Line::from(vec![
                            Span::styled("Model: ", Style::default().fg(Color::Cyan)),
                            Span::raw(e.model.as_deref().unwrap_or("-")),
                        ]),
                        Line::from(""),
                        Line::from("No replacements for this call"),
                    ])
                } else {
                    let mut lines = vec![
                        Line::from(vec![
                            Span::styled("Local: ", Style::default().fg(Color::Cyan)),
                            Span::raw(&e.local_url),
                        ]),
                        Line::from(vec![
                            Span::styled("Remote: ", Style::default().fg(Color::Cyan)),
                            Span::raw(&e.remote_url),
                        ]),
                        Line::from(vec![
                            Span::styled("Model: ", Style::default().fg(Color::Cyan)),
                            Span::raw(e.model.as_deref().unwrap_or("-")),
                        ]),
                        Line::from(""),
                        Line::from(format!("{:<48} | {}", "ORIGINAL", "REPLACED")),
                        Line::from(format!("{:-<48}-+-{:-<48}", "", "")),
                    ];
                    for r in &e.replacements {
                        lines.push(Line::from(format!(
                            "{:<48} | {}",
                            r.original,
                            r.replaced
                        )));
                    }
                    Paragraph::new(lines)
                }
                .wrap(Wrap { trim: false })
                .scroll((self.detail_scroll, 0))
            } else {
                Paragraph::new("No entry selected")
            }
        } else {
            Paragraph::new("No entry selected")
        };

        f.render_widget(
            detail.block(Block::default().borders(Borders::ALL).title(" Details ")),
            area,
        );
    }

    fn render_input(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let (title, content) = match self.input_mode {
            InputMode::Search => (" Search ", self.search_query.as_str()),
            InputMode::Normal => (" Status ", self.status_message.as_str()),
        };

        let input = Paragraph::new(content)
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
                        KeyCode::PageDown => self.detail_scroll = self.detail_scroll.saturating_add(5),
                        KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(5),
                        KeyCode::Char('f') => self.toggle_filter_mode(),
                        _ => {}
                    },
                    InputMode::Search => match key.code {
                        KeyCode::Enter => {
                            self.apply_filters();
                            self.status_message = format!("Searching for: {}", self.search_query);
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Char(c) => self.search_query.push(c),
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
                Constraint::Percentage(35),
                Constraint::Percentage(60),
                Constraint::Percentage(5),
            ])
            .split(f.size());

        self.render_table(f, chunks[0]);
        self.render_detail(f, chunks[1]);
        self.render_input(f, chunks[2]);
    }
}
