use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{
    Attribute, Color as CtColor, Print, ResetColor, SetAttribute, SetForegroundColor,
};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode, size};
use crossterm::{cursor, execute};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Position};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Widget};
use ratatui::{Terminal, TerminalOptions, Viewport};

use crate::source::live::CaptureMsg;
use crate::source::{live, pcap_file};
use std::io::{Stdout, stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type Tui = Terminal<CrosstermBackend<Stdout>>;

const ACCENT: Color = Color::Rgb(215, 119, 87);
const ACCENT_CT: CtColor = CtColor::Rgb {
    r: 215,
    g: 119,
    b: 87,
};
const BANNER_HEIGHT: u16 = 9;
const VIEWPORT_HEIGHT: u16 = 4;

const CRAB: [&str; 4] = [
    "  ▄▄      ▄▄  ",
    " ████▄▄▄▄████ ",
    " ▀██ ▀██▀ ██▀ ",
    "   ▀▀ ▀▀ ▀▀   ",
];

/// A running live capture: the channel it reports on, the flag that stops it,
/// and its thread handle.
struct Session {
    rx: Receiver<CaptureMsg>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    count: usize,
}

/// How many captured lines to render per frame, so a busy network cannot
/// starve the key handling.
const DRAIN_PER_FRAME: usize = 200;

pub fn tui() -> std::io::Result<()> {
    enable_raw_mode()?;
    execute!(
        stdout(),
        Clear(ClearType::Purge),
        Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;

    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(stdout()),
        TerminalOptions {
            viewport: Viewport::Inline(VIEWPORT_HEIGHT),
        },
    )?;

    banner(&mut terminal)?;
    push_to_bottom(&mut terminal)?;

    let mut input = String::new();
    let mut next_row: u16 = BANNER_HEIGHT;
    let mut session: Option<Session> = None;

    loop {
        let mut finished = false;
        if let Some(active) = session.as_mut() {
            for _ in 0..DRAIN_PER_FRAME {
                match active.rx.try_recv() {
                    Ok(CaptureMsg::Line(l)) => {
                        active.count += 1;
                        emit(&mut terminal, &mut next_row, "  ", &l, Tone::Plain)?;
                    }
                    Ok(CaptureMsg::Error(e)) => {
                        emit(&mut terminal, &mut next_row, "  ", &e, Tone::Error)?
                    }
                    Ok(CaptureMsg::Ended) | Err(TryRecvError::Disconnected) => {
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
        }
        if finished {
            if let Some(mut active) = session.take() {
                if let Some(h) = active.handle.take() {
                    let _ = h.join();
                }
                let msg = format!("capture stopped - {} packets", active.count);
                emit(&mut terminal, &mut next_row, "  ", &msg, Tone::Dim)?;
            }
        }

        let capturing = session.as_ref().map(|s| s.count);

        terminal.draw(|frame| {
            let [box_area, footer_area] =
                Layout::vertical([Constraint::Length(3), Constraint::Length(1)])
                    .areas(frame.area());

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(ACCENT));

            let prompt = Line::from(vec![
                Span::styled("> ", Style::new().fg(ACCENT)),
                Span::raw(input.as_str()),
            ]);
            frame.render_widget(Paragraph::new(prompt).block(block), box_area);

            let footer = match capturing {
                Some(n) => Line::from(vec![
                    Span::styled("capturing", Style::new().fg(ACCENT)),
                    Span::raw(format!(" {} packets", n)).dim(),
                    Span::raw("   ").dim(),
                    Span::styled("esc", Style::new().fg(ACCENT)),
                    Span::raw(" stop").dim(),
                ]),
                None => Line::from(vec![
                    Span::styled("enter", Style::new().fg(ACCENT)),
                    Span::raw(" run").dim(),
                    Span::raw("   ").dim(),
                    Span::styled("ctrl-c", Style::new().fg(ACCENT)),
                    Span::raw(" quit").dim(),
                ]),
            };
            frame.render_widget(Paragraph::new(footer), footer_area);

            let cursor_x = box_area.x + 3 + input.chars().count() as u16;
            frame.set_cursor_position(Position::new(cursor_x, box_area.y + 1));
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        match session.as_ref() {
                            Some(active) => active.stop.store(true, Ordering::Relaxed),
                            None => break,
                        }
                    }
                    KeyCode::Esc => {
                        if let Some(active) = session.as_ref() {
                            active.stop.store(true, Ordering::Relaxed);
                        }
                    }
                    KeyCode::Char(c) => input.push(c),
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Enter => {
                        let line = input.trim().to_string();
                        input.clear();
                        if line == "exit" || line == "quit" {
                            break;
                        }
                        if !line.is_empty() {
                            emit(&mut terminal, &mut next_row, "› ", &line, Tone::Accent)?;
                            run_command(&mut terminal, &mut next_row, &line, &mut session)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(mut active) = session.take() {
        active.stop.store(true, Ordering::Relaxed);
        if let Some(h) = active.handle.take() {
            let _ = h.join();
        }
    }

    disable_raw_mode()?;
    terminal.clear()?;
    Ok(())
}

/// Draws the startup banner into the scrollback above the viewport.
fn banner(terminal: &mut Tui) -> std::io::Result<()> {
    terminal.insert_before(BANNER_HEIGHT, |buf| {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(ACCENT))
            .title(Span::styled(
                format!(" RustyGrab v{} ", env!("CARGO_PKG_VERSION")),
                Style::new().fg(ACCENT).bold(),
            ));
        let inner = block.inner(buf.area);
        block.render(buf.area, buf);

        let mut lines: Vec<Line> = CRAB
            .iter()
            .map(|row| Line::from(Span::styled(*row, Style::new().fg(ACCENT))))
            .collect();
        lines.push(Line::from(""));
        lines.push(Line::from(
            "packet analyzer · type help for commands".dim(),
        ));

        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .render(inner, buf);
    })?;
    Ok(())
}

/// Pads below the banner so the input box starts pinned to the bottom.
fn push_to_bottom(terminal: &mut Tui) -> std::io::Result<()> {
    let (_cols, rows) = size()?;
    let gap = rows.saturating_sub(BANNER_HEIGHT + VIEWPORT_HEIGHT);
    if gap > 0 {
        terminal.insert_before(gap, |_buf| {})?;
    }
    Ok(())
}

/// How an emitted line should be coloured.
#[derive(Clone, Copy)]
enum Tone {
    Plain,
    Dim,
    Error,
    Accent,
}

/// Writes one output line. While there is untouched space between the banner
/// and the input box, the line is drawn there directly so output grows
/// downwards. Once that space is used up, lines are inserted above the
/// viewport instead, which scrolls the banner off the top.
fn emit(
    terminal: &mut Tui,
    next_row: &mut u16,
    marker: &str,
    text: &str,
    tone: Tone,
) -> std::io::Result<()> {
    let (_cols, rows) = size()?;
    let last_free_row = rows.saturating_sub(VIEWPORT_HEIGHT + 1);

    if *next_row <= last_free_row {
        execute!(stdout(), cursor::MoveTo(0, *next_row))?;
        if !marker.is_empty() {
            execute!(
                stdout(),
                SetForegroundColor(ACCENT_CT),
                Print(marker),
                ResetColor
            )?;
        }
        match tone {
            Tone::Plain => execute!(stdout(), Print(text))?,
            Tone::Dim => execute!(
                stdout(),
                SetAttribute(Attribute::Dim),
                Print(text),
                SetAttribute(Attribute::Reset)
            )?,
            Tone::Error => execute!(
                stdout(),
                SetForegroundColor(CtColor::Red),
                Print(text),
                ResetColor
            )?,
            Tone::Accent => execute!(
                stdout(),
                SetForegroundColor(ACCENT_CT),
                Print(text),
                ResetColor
            )?,
        }
        *next_row += 1;
    } else {
        let owned_marker = marker.to_string();
        let owned_text = text.to_string();
        let style = match tone {
            Tone::Plain => Style::new(),
            Tone::Dim => Style::new().dim(),
            Tone::Error => Style::new().fg(Color::Red),
            Tone::Accent => Style::new().fg(ACCENT),
        };
        terminal.insert_before(1, |buf| {
            Line::from(vec![
                Span::styled(owned_marker, Style::new().fg(ACCENT)),
                Span::styled(owned_text, style),
            ])
            .render(buf.area, buf);
        })?;
    }
    Ok(())
}

/// Parses a submitted line and runs the matching command, emitting its output.
fn run_command(
    terminal: &mut Tui,
    next_row: &mut u16,
    line: &str,
    session: &mut Option<Session>,
) -> std::io::Result<()> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (cmd, rest) = match parts.split_first() {
        Some((c, r)) => (*c, r),
        None => return Ok(()),
    };

    match cmd {
        "help" => {
            for (name, desc) in HELP {
                emit(terminal, next_row, "  ", &format!("{:<20}{}", name, desc), Tone::Dim)?;
            }
        }
        "version" => emit(
            terminal,
            next_row,
            "  ",
            &format!("rustygrab {}", env!("CARGO_PKG_VERSION")),
            Tone::Dim,
        )?,
        "read" => match rest.first() {
            None => emit(terminal, next_row, "  ", "usage: read <file.pcap>", Tone::Error)?,
            Some(path) => match pcap_file::read_file(path) {
                Err(e) => emit(terminal, next_row, "  ", &e, Tone::Error)?,
                Ok(result) => {
                    for packet in &result.packets {
                        emit(terminal, next_row, "  ", &packet.summary(), Tone::Plain)?;
                    }
                    if let Some(w) = result.warning {
                        emit(terminal, next_row, "  ", &w, Tone::Error)?;
                    }
                    emit(
                        terminal,
                        next_row,
                        "  ",
                        &format!("{} packets from {}", result.packets.len(), path),
                        Tone::Dim,
                    )?;
                }
            },
        },
        "devices" => match live::list_devices() {
            Err(e) => emit(terminal, next_row, "  ", &e, Tone::Error)?,
            Ok(lines) => {
                for l in lines {
                    emit(terminal, next_row, "  ", &l, Tone::Plain)?;
                }
            }
        },
        "live" => {
            if session.is_some() {
                emit(
                    terminal,
                    next_row,
                    "  ",
                    "a capture is already running - press esc to stop it",
                    Tone::Error,
                )?;
            } else {
                match rest.first().map(|s| s.parse::<usize>()) {
                    None => emit(terminal, next_row, "  ", "usage: live <index>", Tone::Error)?,
                    Some(Err(_)) => emit(
                        terminal,
                        next_row,
                        "  ",
                        "interface index must be a number - try devices",
                        Tone::Error,
                    )?,
                    Some(Ok(index)) => {
                        let (tx, rx) = mpsc::channel();
                        let stop = Arc::new(AtomicBool::new(false));
                        let thread_stop = Arc::clone(&stop);
                        let handle =
                            thread::spawn(move || live::capture_loop(index, tx, thread_stop));
                        *session = Some(Session {
                            rx,
                            stop,
                            handle: Some(handle),
                            count: 0,
                        });
                        emit(
                            terminal,
                            next_row,
                            "  ",
                            &format!("capturing on interface {} - esc to stop", index),
                            Tone::Dim,
                        )?;
                    }
                }
            }
        }
        other => emit(
            terminal,
            next_row,
            "  ",
            &format!("unknown command: {} (try help)", other),
            Tone::Error,
        )?,
    }
    Ok(())
}

const HELP: [(&str, &str); 6] = [
    ("read <file.pcap>", "decode packets from a capture file"),
    ("devices", "list available network interfaces"),
    ("live <index>", "capture live traffic (not yet available here)"),
    ("help", "show this help"),
    ("version", "show version"),
    ("exit", "quit rustygrab"),
];
