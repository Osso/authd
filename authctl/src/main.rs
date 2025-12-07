use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use iced::keyboard::{self, Key};
use iced::widget::{column, container, row, text, horizontal_rule};
use iced::border::Radius;
use iced::Color;
use iced_layershell::Appearance;
use iced::theme::Palette;
use iced::{Element, Subscription, Task, Theme};
use iced_layershell::reexport::{Anchor, KeyboardInteractivity};
use iced_layershell::settings::{LayerShellSettings, Settings};
use iced_layershell::Application;
use iced_layershell::to_layer_message;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub fn main() -> Result<(), iced_layershell::Error> {
    let args: Vec<String> = env::args().skip(1).collect();
    let (target, target_args) = parse_args(&args);

    App::run(Settings {
        layer_settings: LayerShellSettings {
            size: Some((450, 200)),
            anchor: Anchor::empty(),
            keyboard_interactivity: KeyboardInteractivity::OnDemand,
            ..Default::default()
        },
        flags: (target, target_args),
        ..Default::default()
    })
}

struct App {
    target: PathBuf,
    args: Vec<String>,
    status: Status,
}

#[derive(Default, Clone)]
enum Status {
    #[default]
    Ready,
    Confirming,
    Success,
    Failed(String),
}

#[to_layer_message]
#[derive(Debug, Clone)]
enum Message {
    Confirm,
    Cancel,
    AuthResult(Result<AuthResponse, String>),
}

impl Application for App {
    type Message = Message;
    type Flags = (PathBuf, Vec<String>);
    type Theme = Theme;
    type Executor = iced::executor::Default;

    fn new(flags: Self::Flags) -> (Self, Task<Self::Message>) {
        (
            Self {
                target: flags.0,
                args: flags.1,
                status: Status::Ready,
            },
            Task::none(),
        )
    }

    fn namespace(&self) -> String {
        "authctl".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        match message {
            Message::Confirm => {
                self.status = Status::Confirming;
                let request = AuthRequest {
                    target: self.target.clone(),
                    args: self.args.clone(),
                    env: collect_wayland_env(),
                    password: String::new(),
                };
                Task::perform(send_request(request), Message::AuthResult)
            }
            Message::Cancel => {
                std::process::exit(1);
            }
            Message::AuthResult(result) => {
                match result {
                    Ok(AuthResponse::Success { pid: _ }) => {
                        self.status = Status::Success;
                        std::process::exit(0);
                    }
                    Ok(AuthResponse::Denied { reason }) => {
                        self.status = Status::Failed(format!("Denied: {}", reason));
                    }
                    Ok(AuthResponse::UnknownTarget) => {
                        self.status = Status::Failed(
                            "No policy found for this program".into()
                        );
                    }
                    Ok(AuthResponse::AuthFailed) => {
                        self.status = Status::Failed("Authentication failed".into());
                    }
                    Ok(AuthResponse::Error { message }) => {
                        self.status = Status::Failed(format!("Error: {}", message));
                    }
                    Err(e) => {
                        let msg = if e.contains("connect:") {
                            "authd daemon is not running".into()
                        } else {
                            format!("Connection error: {}", e)
                        };
                        self.status = Status::Failed(msg);
                    }
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Self::Message, Self::Theme, iced::Renderer> {
        let title = text("Authorization Required").size(20);

        let target_display = self.target.display().to_string();
        let command = if self.args.is_empty() {
            target_display
        } else {
            format!("{} {}", target_display, self.args.join(" "))
        };
        let command_text = text(command).size(14);

        let status_text = match &self.status {
            Status::Ready => text(""),
            Status::Confirming => text("Authorizing...").size(14),
            Status::Success => text("Success!").size(14),
            Status::Failed(msg) => text(msg.as_str()).size(14),
        };

        let theme = ayu_dark_theme();
        let actions = row![
            text("[Enter] Allow").size(14).color(theme.palette().success),
            text("[Esc] Cancel").size(14).color(theme.palette().danger),
        ]
        .spacing(20);

        let content = column![
            title,
            horizontal_rule(1),
            text("An application wants to run as root:").size(12),
            command_text,
            status_text,
            actions,
        ]
        .spacing(12)
        .padding(20);

        container(content)
            .center_x(450)
            .center_y(200)
            .style(|_theme| container::Style {
                background: Some(Color::from_rgba(0.118, 0.133, 0.165, 0.98).into()),
                border: iced::Border {
                    color: Color::from_rgb8(0x56, 0x5B, 0x66), // mOutline
                    width: 1.0,
                    radius: Radius::from(12.0),
                },
                ..Default::default()
            })
            .into()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        keyboard::on_key_press(|key, _modifiers| match key {
            Key::Named(keyboard::key::Named::Enter) => Some(Message::Confirm),
            Key::Named(keyboard::key::Named::Escape) => Some(Message::Cancel),
            _ => None,
        })
    }

    fn theme(&self) -> Theme {
        ayu_dark_theme()
    }

    fn style(&self, theme: &Self::Theme) -> Appearance {
        Appearance {
            background_color: Color::TRANSPARENT,
            text_color: theme.palette().text,
        }
    }
}

fn ayu_dark_theme() -> Theme {
    // Colors from quickshell Ayu.json
    Theme::custom(
        "Ayu Dark".to_string(),
        Palette {
            background: Color::from_rgb8(0x0B, 0x0E, 0x14), // mSurfaceVariant
            text: Color::from_rgb8(0xBF, 0xBD, 0xB6),       // mOnSurface
            primary: Color::from_rgb8(0xE6, 0xB4, 0x50),    // mPrimary (yellow)
            success: Color::from_rgb8(0xAA, 0xD9, 0x4C),    // mSecondary (green)
            danger: Color::from_rgb8(0xD9, 0x57, 0x57),     // mError (red)
        },
    )
}

fn parse_args(args: &[String]) -> (PathBuf, Vec<String>) {
    let target = args.first().map(PathBuf::from).unwrap_or_default();
    let target_args = args.get(1..).map(|s| s.to_vec()).unwrap_or_default();
    (target, target_args)
}

fn collect_wayland_env() -> HashMap<String, String> {
    wayland_env()
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|val| (key.to_string(), val)))
        .collect()
}

async fn send_request(request: AuthRequest) -> Result<AuthResponse, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .map_err(|e| format!("connect: {}", e))?;

    let data = rmp_serde::to_vec(&request).map_err(|e| format!("serialize: {}", e))?;
    stream
        .write_all(&data)
        .await
        .map_err(|e| format!("write: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("read: {}", e))?;

    rmp_serde::from_slice(&buf[..n]).map_err(|e| format!("deserialize: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_empty() {
        let (target, args) = parse_args(&[]);
        assert_eq!(target, PathBuf::from(""));
        assert!(args.is_empty());
    }

    #[test]
    fn parse_args_target_only() {
        let input = vec!["/usr/bin/test".to_string()];
        let (target, args) = parse_args(&input);
        assert_eq!(target, PathBuf::from("/usr/bin/test"));
        assert!(args.is_empty());
    }

    #[test]
    fn parse_args_with_arguments() {
        let input = vec![
            "/usr/bin/test".to_string(),
            "--flag".to_string(),
            "value".to_string(),
        ];
        let (target, args) = parse_args(&input);
        assert_eq!(target, PathBuf::from("/usr/bin/test"));
        assert_eq!(args, vec!["--flag", "value"]);
    }

    #[test]
    fn collect_wayland_env_returns_hashmap() {
        // Just verify it returns a valid hashmap (content depends on environment)
        let env_map = collect_wayland_env();
        // Should only contain keys from wayland_env()
        for key in env_map.keys() {
            assert!(wayland_env().contains(&key.as_str()));
        }
    }
}
