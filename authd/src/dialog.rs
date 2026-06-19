//! Confirmation dialog for authd using session-dialog library
//!
//! Shows a secure session-lock confirmation dialog via the session-dialog crate.

use peercred_ipc::CallerInfo;
use session_dialog::{DialogConfig, DialogKind, DialogResult as SdResult};
use std::collections::HashMap;
use std::path::PathBuf;

const REQUIRED_SESSION_ENV: &[&str] = &["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"];

/// Result of showing the confirmation dialog
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DialogResult {
    Confirmed,
    Denied,
    Error,
}

/// Show a confirmation dialog using session-dialog
///
/// Runs the dialog inline (no fork) with the caller's Wayland env vars.
/// The dialog locks the session and shows a confirmation prompt.
pub fn show_confirmation_dialog(
    _caller: &CallerInfo,
    target: &PathBuf,
    args: &[String],
    env: &HashMap<String, String>,
    prompt_title: Option<&str>,
    prompt_message: Option<&str>,
    prompt_detail: Option<&str>,
) -> DialogResult {
    if !has_reachable_session_env(env) {
        return DialogResult::Error;
    }

    let config = DialogConfig {
        kind: dialog_kind(target, args, prompt_title, prompt_message, prompt_detail),
        timeout_secs: Some(30),
    };

    // Run in separate thread to avoid tokio runtime conflicts
    let handle = session_dialog::show_dialog_async(config, env.clone());
    let result = handle.join().unwrap_or(SdResult::Error);

    match result {
        SdResult::Confirmed => DialogResult::Confirmed,
        SdResult::Denied | SdResult::Timeout => DialogResult::Denied,
        SdResult::Error => DialogResult::Error,
    }
}

fn dialog_kind(
    target: &PathBuf,
    args: &[String],
    prompt_title: Option<&str>,
    prompt_message: Option<&str>,
    prompt_detail: Option<&str>,
) -> DialogKind {
    match (prompt_title, prompt_message, prompt_detail) {
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

fn command_text(target: &PathBuf, args: &[String]) -> String {
    if args.is_empty() {
        target.to_string_lossy().to_string()
    } else {
        format!("{} {}", target.display(), args.join(" "))
    }
}

/// Show a confirmation dialog for a polkit authentication request.
///
/// Uses polkit's own human-readable `message` as the prompt and the action id
/// as the detail line. Allow/Deny only — no password entry.
pub fn show_polkit_dialog(
    message: &str,
    action_id: &str,
    env: &HashMap<String, String>,
) -> DialogResult {
    if !has_reachable_session_env(env) {
        return DialogResult::Error;
    }

    let config = DialogConfig {
        kind: DialogKind::Generic {
            title: "Authorization Required".to_string(),
            message: message.to_string(),
            detail: action_id.to_string(),
        },
        timeout_secs: Some(30),
    };

    let handle = session_dialog::show_dialog_async(config, env.clone());
    match handle.join().unwrap_or(SdResult::Error) {
        SdResult::Confirmed => DialogResult::Confirmed,
        SdResult::Denied | SdResult::Timeout => DialogResult::Denied,
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

    #[test]
    fn polkit_dialog_returns_error_without_session_env() {
        let result = show_polkit_dialog(
            "Authentication is required.",
            "org.freedesktop.systemd1.manage-units",
            &HashMap::new(),
        );

        assert_eq!(result, DialogResult::Error);
    }
}
