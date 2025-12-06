use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use iced::keyboard::{self, Key};
use iced::widget::{column, container, text};
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
                    Ok(resp) => {
                        self.status = Status::Failed(format!("{:?}", resp));
                    }
                    Err(e) => {
                        self.status = Status::Failed(e);
                    }
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Self::Message, Self::Theme, iced::Renderer> {
        let title = text("Run as root:").size(18);
        let target_text = text(format!("{:?}", self.target)).size(14);

        let hint = text("Press Enter to confirm, Esc to cancel").size(12);

        let status_text = match &self.status {
            Status::Ready => text(""),
            Status::Confirming => text("Authorizing..."),
            Status::Success => text("Success!"),
            Status::Failed(msg) => text(msg.as_str()),
        };

        let content = column![title, target_text, hint, status_text]
            .spacing(12)
            .padding(20);

        container(content).into()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        keyboard::on_key_press(|key, _modifiers| match key {
            Key::Named(keyboard::key::Named::Enter) => Some(Message::Confirm),
            Key::Named(keyboard::key::Named::Escape) => Some(Message::Cancel),
            _ => None,
        })
    }
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
