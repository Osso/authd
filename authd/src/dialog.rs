//! Confirmation dialog for authd using session-dialog library
//!
//! Shows a secure session-lock confirmation dialog via the session-dialog crate.

use peercred_ipc::CallerInfo;
use session_dialog::{DialogConfig, DialogKind, DialogResult as SdResult};
use std::collections::HashMap;
use std::path::PathBuf;

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
) -> DialogResult {
    // Build command string for dialog
    let command = if args.is_empty() {
        target.to_string_lossy().to_string()
    } else {
        format!("{} {}", target.display(), args.join(" "))
    };

    let config = DialogConfig {
        kind: DialogKind::PrivilegeEscalation { command },
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
