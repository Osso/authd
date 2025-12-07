//! authd-dialog - Session lock confirmation dialog
//!
//! This binary is exec'd by authd to show a secure session-lock dialog.
//! It receives the command to authorize via command line args.

use iced::border::Radius;
use iced::keyboard::{self, Key};
use iced::theme::Palette;
use iced::widget::{column, container, horizontal_rule, row, text};
use iced::window::Id;
use iced::Color;
use iced::{Element, Event, Subscription, Task, Theme};
use iced_sessionlock::build_pattern::application;
use iced_sessionlock::to_session_message;
use std::env;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static TARGET_COMMAND: OnceLock<String> = OnceLock::new();
static CANCELLED: AtomicBool = AtomicBool::new(false);

fn main() {
    // Get command from args
    let args: Vec<String> = env::args().skip(1).collect();
    let command = if args.is_empty() {
        "unknown command".to_string()
    } else {
        args.join(" ")
    };
    let _ = TARGET_COMMAND.set(command);

    let result = application(App::update, App::view)
        .theme(App::theme)
        .subscription(App::subscription)
        .run_with(App::new);

    match result {
        Ok(()) => {
            // Check if user cancelled (Esc) vs confirmed (Enter)
            if CANCELLED.load(Ordering::SeqCst) {
                std::process::exit(1);
            } else {
                std::process::exit(0);
            }
        }
        Err(_) => std::process::exit(1),
    }
}

struct App;

#[to_session_message]
#[derive(Debug, Clone)]
enum Message {
    Event(Event),
}

impl App {
    fn new() -> (Self, Task<Message>) {
        (Self, Task::none())
    }

    fn theme(_: &Self) -> Theme {
        ayu_dark_theme()
    }

    fn subscription(_: &Self) -> Subscription<Message> {
        iced::event::listen().map(Message::Event)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Event(Event::Keyboard(keyboard::Event::KeyPressed { key, .. })) => {
                match key {
                    Key::Named(keyboard::key::Named::Enter) => {
                        Task::done(Message::UnLock)
                    }
                    Key::Named(keyboard::key::Named::Escape) => {
                        // Mark as cancelled, then unlock (must unlock before exit)
                        CANCELLED.store(true, Ordering::SeqCst);
                        Task::done(Message::UnLock)
                    }
                    _ => Task::none(),
                }
            }
            _ => Task::none(),
        }
    }

    fn view(&self, _id: Id) -> Element<'_, Message> {
        let command = TARGET_COMMAND.get().map(|s| s.as_str()).unwrap_or("unknown");

        let title = text("Authorization Required").size(24);
        let command_text = text(command).size(16);

        let theme = ayu_dark_theme();
        let actions = row![
            text("[Enter] Allow").size(16).color(theme.palette().success),
            text("[Esc] Cancel").size(16).color(theme.palette().danger),
        ]
        .spacing(30);

        let content = column![
            title,
            horizontal_rule(1),
            text("An application wants to run as root:").size(14),
            command_text,
            actions,
        ]
        .spacing(16)
        .padding(30);

        container(content)
            .center_x(iced::Length::Fill)
            .center_y(iced::Length::Fill)
            .style(|_theme| container::Style {
                background: Some(Color::from_rgba(0.05, 0.06, 0.08, 0.95).into()),
                border: iced::Border {
                    color: Color::from_rgb8(0x56, 0x5B, 0x66),
                    width: 2.0,
                    radius: Radius::from(16.0),
                },
                ..Default::default()
            })
            .into()
    }
}

fn ayu_dark_theme() -> Theme {
    Theme::custom(
        "Ayu Dark".to_string(),
        Palette {
            background: Color::from_rgb8(0x0B, 0x0E, 0x14),
            text: Color::from_rgb8(0xBF, 0xBD, 0xB6),
            primary: Color::from_rgb8(0xE6, 0xB4, 0x50),
            success: Color::from_rgb8(0xAA, 0xD9, 0x4C),
            danger: Color::from_rgb8(0xD9, 0x57, 0x57),
        },
    )
}
