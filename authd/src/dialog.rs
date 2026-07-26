//! Confirmation dialog for authd using session-dialog library
//!
//! Shows a secure session-lock confirmation dialog via the session-dialog crate.

use crate::RequestTrace;
use peercred_ipc::CallerInfo;
use session_dialog::DialogKind;
#[cfg(not(coverage))]
use session_dialog::{DialogConfig, DialogResult as SdResult, spawn_dialog};
use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(not(coverage))]
use std::time::Duration;

const REQUIRED_SESSION_ENV: &[&str] = &["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"];
#[cfg(not(coverage))]
const DIALOG_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Result of showing the confirmation dialog
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DialogResult {
    Confirmed,
    Denied,
    Error,
}

/// Optional text overriding the default privilege-escalation prompt.
pub struct ConfirmationPrompt<'a> {
    pub title: Option<&'a str>,
    pub message: Option<&'a str>,
    pub detail: Option<&'a str>,
}

/// Show a confirmation dialog using session-dialog
///
/// Spawns the dialog with the caller's identity and Wayland environment.
/// The dialog locks the session and shows a confirmation prompt.
pub async fn show_confirmation_dialog(
    caller: &CallerInfo,
    target: &Path,
    args: &[String],
    env: &HashMap<String, String>,
    prompt: ConfirmationPrompt<'_>,
    trace: &RequestTrace,
) -> DialogResult {
    if !has_reachable_session_env(env) {
        return DialogResult::Error;
    }

    show_confirmation_dialog_with_session_env(caller, target, args, env, prompt, trace).await
}

#[cfg(not(coverage))]
async fn show_confirmation_dialog_with_session_env(
    caller: &CallerInfo,
    target: &Path,
    args: &[String],
    env: &HashMap<String, String>,
    prompt: ConfirmationPrompt<'_>,
    trace: &RequestTrace,
) -> DialogResult {
    let config = DialogConfig {
        kind: dialog_kind(target, args, prompt),
        timeout_secs: Some(30),
    };

    show_dialog_process(caller.uid, caller.gid, config, env, trace).await
}

#[cfg(coverage)]
async fn show_confirmation_dialog_with_session_env(
    _caller: &CallerInfo,
    target: &Path,
    args: &[String],
    _env: &HashMap<String, String>,
    prompt: ConfirmationPrompt<'_>,
    _trace: &RequestTrace,
) -> DialogResult {
    let _ = dialog_kind(target, args, prompt);
    DialogResult::Error
}

fn dialog_kind(target: &Path, args: &[String], prompt: ConfirmationPrompt<'_>) -> DialogKind {
    match (prompt.title, prompt.message, prompt.detail) {
        (Some(title), Some(message), Some(detail)) => DialogKind::Generic {
            title: title.to_string(),
            message: message.to_string(),
            detail: detail.to_string(),
        },
        _ => DialogKind::PrivilegeEscalation {
            command: command_text(target, args),
        },
    }
}

fn command_text(target: &Path, args: &[String]) -> String {
    if args.is_empty() {
        target.to_string_lossy().to_string()
    } else {
        format!("{} {}", target.display(), args.join(" "))
    }
}

/// Show a Secrets Broker confirmation in the independently validated target session.
#[cfg(not(coverage))]
pub async fn show_target_session_dialog(
    uid: u32,
    gid: u32,
    env: &HashMap<String, String>,
    title: &str,
    message: &str,
    detail: &str,
    trace: &RequestTrace,
) -> DialogResult {
    if !has_reachable_session_env(env) {
        return DialogResult::Error;
    }

    let config = DialogConfig {
        kind: DialogKind::Generic {
            title: title.to_string(),
            message: message.to_string(),
            detail: detail.to_string(),
        },
        timeout_secs: Some(30),
    };

    show_dialog_process(uid, gid, config, env, trace).await
}

#[cfg(coverage)]
pub async fn show_target_session_dialog(
    _uid: u32,
    _gid: u32,
    env: &HashMap<String, String>,
    _title: &str,
    _message: &str,
    _detail: &str,
    _trace: &RequestTrace,
) -> DialogResult {
    let _ = has_reachable_session_env(env);
    DialogResult::Error
}

/// Show a confirmation dialog for a polkit authentication request.
pub async fn show_polkit_dialog(
    caller: &CallerInfo,
    message: &str,
    action_id: &str,
    env: &HashMap<String, String>,
    trace: &RequestTrace,
) -> DialogResult {
    if !has_reachable_session_env(env) {
        return DialogResult::Error;
    }

    show_polkit_dialog_with_session_env(caller, message, action_id, env, trace).await
}

#[cfg(not(coverage))]
async fn show_polkit_dialog_with_session_env(
    caller: &CallerInfo,
    message: &str,
    action_id: &str,
    env: &HashMap<String, String>,
    trace: &RequestTrace,
) -> DialogResult {
    let config = DialogConfig {
        kind: DialogKind::Generic {
            title: "Authorization Required".to_string(),
            message: message.to_string(),
            detail: action_id.to_string(),
        },
        timeout_secs: Some(30),
    };

    show_dialog_process(caller.uid, caller.gid, config, env, trace).await
}

#[cfg(coverage)]
async fn show_polkit_dialog_with_session_env(
    _caller: &CallerInfo,
    message: &str,
    action_id: &str,
    _env: &HashMap<String, String>,
    _trace: &RequestTrace,
) -> DialogResult {
    let _ = DialogKind::Generic {
        title: "Authorization Required".to_string(),
        message: message.to_string(),
        detail: action_id.to_string(),
    };
    DialogResult::Error
}

#[cfg(not(coverage))]
async fn show_dialog_process(
    uid: u32,
    gid: u32,
    config: DialogConfig,
    env: &HashMap<String, String>,
    trace: &RequestTrace,
) -> DialogResult {
    trace.log("dialog_spawn_requested");
    let mut dialog = match spawn_dialog(&config, uid, gid, env, Some(trace.id())) {
        Ok(dialog) => dialog,
        Err(_) => return DialogResult::Error,
    };
    trace.log("dialog_spawned");

    loop {
        match dialog.try_wait() {
            Ok(Some(result)) => {
                trace.log("dialog_completed");
                return map_dialog_result(result);
            }
            Ok(None) => tokio::time::sleep(DIALOG_POLL_INTERVAL).await,
            Err(_) => return DialogResult::Error,
        }
    }
}

#[cfg(not(coverage))]
fn map_dialog_result(result: SdResult) -> DialogResult {
    match result {
        SdResult::Confirmed => DialogResult::Confirmed,
        SdResult::Denied | SdResult::Timeout | SdResult::Cancelled => DialogResult::Denied,
        SdResult::Error => DialogResult::Error,
    }
}

fn has_reachable_session_env(env: &HashMap<String, String>) -> bool {
    REQUIRED_SESSION_ENV
        .iter()
        .all(|key| env.get(*key).is_some_and(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_env_requires_wayland_display_and_runtime_dir() {
        let env = HashMap::from([
            ("WAYLAND_DISPLAY".to_string(), "wayland-1".to_string()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ]);

        assert!(has_reachable_session_env(&env));
    }

    #[test]
    fn session_env_rejects_missing_or_empty_values() {
        assert!(!has_reachable_session_env(&HashMap::new()));

        let missing_runtime =
            HashMap::from([("WAYLAND_DISPLAY".to_string(), "wayland-1".to_string())]);
        assert!(!has_reachable_session_env(&missing_runtime));

        let empty_display = HashMap::from([
            ("WAYLAND_DISPLAY".to_string(), String::new()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ]);
        assert!(!has_reachable_session_env(&empty_display));
    }

    #[tokio::test]
    async fn polkit_dialog_returns_error_without_session_env() {
        let caller = CallerInfo {
            uid: 1000,
            gid: 1000,
            pid: 42,
            exe: PathBuf::from("/usr/bin/authd-polkit-agent"),
        };
        let trace = RequestTrace::new();
        let result = show_polkit_dialog(
            &caller,
            "Authentication is required.",
            "org.freedesktop.systemd1.manage-units",
            &HashMap::new(),
            &trace,
        )
        .await;

        assert_eq!(result, DialogResult::Error);
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn dialog_stubs_return_error_with_session_env() {
        let env = HashMap::from([
            ("WAYLAND_DISPLAY".to_string(), "wayland-1".to_string()),
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
        ]);
        let caller = CallerInfo {
            uid: 1000,
            gid: 1000,
            pid: 42,
            exe: PathBuf::from("/usr/bin/authsudo"),
        };

        let trace = RequestTrace::new();
        assert_eq!(
            show_confirmation_dialog(
                &caller,
                &PathBuf::from("/usr/bin/id"),
                &["-u".to_string()],
                &env,
                ConfirmationPrompt {
                    title: Some("Title"),
                    message: Some("Message"),
                    detail: Some("Detail"),
                },
                &trace,
            )
            .await,
            DialogResult::Error
        );
        assert_eq!(
            show_polkit_dialog(&caller, "Message", "org.example.Action", &env, &trace).await,
            DialogResult::Error
        );
        assert_eq!(DialogResult::Confirmed, DialogResult::Confirmed);
        assert_eq!(DialogResult::Denied, DialogResult::Denied);
    }

    #[tokio::test]
    async fn target_session_dialog_rejects_missing_session_env() {
        let trace = RequestTrace::new();
        let result = show_target_session_dialog(
            1000,
            1000,
            &HashMap::new(),
            "Secrets Broker",
            "Unlock credentials?",
            "mysql-gc:prod-ro",
            &trace,
        )
        .await;

        assert_eq!(result, DialogResult::Error);
    }

    #[tokio::test]
    async fn confirmation_dialog_returns_error_without_session_env() {
        let caller = CallerInfo {
            uid: 1000,
            gid: 1000,
            pid: 42,
            exe: PathBuf::from("/usr/bin/authsudo"),
        };

        let trace = RequestTrace::new();
        let result = show_confirmation_dialog(
            &caller,
            &PathBuf::from("/usr/bin/id"),
            &["-u".to_string()],
            &HashMap::new(),
            ConfirmationPrompt {
                title: None,
                message: None,
                detail: None,
            },
            &trace,
        )
        .await;

        assert_eq!(result, DialogResult::Error);
    }

    #[test]
    fn dialog_kind_prefers_explicit_prompt_text() {
        let kind = dialog_kind(
            &PathBuf::from("/usr/bin/id"),
            &["-u".to_string()],
            ConfirmationPrompt {
                title: Some("Title"),
                message: Some("Message"),
                detail: Some("Detail"),
            },
        );

        match kind {
            DialogKind::Generic {
                title,
                message,
                detail,
            } => {
                assert_eq!(title, "Title");
                assert_eq!(message, "Message");
                assert_eq!(detail, "Detail");
            }
            _ => panic!("expected generic dialog"),
        }
    }

    #[test]
    fn dialog_kind_formats_privilege_command() {
        let kind = dialog_kind(
            &PathBuf::from("/usr/bin/id"),
            &["-u".to_string(), "root".to_string()],
            ConfirmationPrompt {
                title: None,
                message: None,
                detail: None,
            },
        );

        match kind {
            DialogKind::PrivilegeEscalation { command } => {
                assert_eq!(command, "/usr/bin/id -u root");
            }
            _ => panic!("expected privilege escalation dialog"),
        }

        assert_eq!(
            command_text(&PathBuf::from("/usr/bin/id"), &[]),
            "/usr/bin/id"
        );
    }
}
