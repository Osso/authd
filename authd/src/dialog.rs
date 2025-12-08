//! Confirmation dialog for authd using ext-session-lock
//!
//! Spawns authd-dialog with dropped privileges to show a secure
//! session-lock confirmation dialog.

use authd_protocol::{CallerInfo, wayland_env};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Result of showing the confirmation dialog
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DialogResult {
    Confirmed,
    Denied,
    Error,
}

/// Show a confirmation dialog by spawning authd-dialog
///
/// Spawns authd-dialog with the caller's UID/GID and Wayland env vars.
/// The dialog locks the session and shows a confirmation prompt.
pub fn show_confirmation_dialog(
    caller: &CallerInfo,
    target: &PathBuf,
    args: &[String],
    env: &HashMap<String, String>,
) -> DialogResult {
    // Find authd-dialog binary (same directory as authd, or /usr/bin)
    let dialog_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("authd-dialog")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/authd-dialog"));

    // Build command string for dialog
    let command = if args.is_empty() {
        target.to_string_lossy().to_string()
    } else {
        format!("{} {}", target.display(), args.join(" "))
    };

    // Get username and home directory
    let username = get_username(caller.uid).unwrap_or_else(|| "nobody".into());
    let home = format!("/home/{}", username);

    // Spawn authd-dialog with dropped privileges
    let result = Command::new(&dialog_bin)
        .arg(&command)
        .uid(caller.uid)
        .gid(caller.gid)
        .env("HOME", &home)
        .env("USER", &username)
        .envs(
            // Only pass known safe Wayland env vars, not arbitrary client data
            wayland_env()
                .iter()
                .filter_map(|&key| env.get(key).map(|val| (key, val)))
        )
        .status();

    match result {
        Ok(status) => {
            if status.success() {
                DialogResult::Confirmed
            } else {
                DialogResult::Denied
            }
        }
        Err(e) => {
            tracing::error!("failed to spawn authd-dialog: {}", e);
            DialogResult::Error
        }
    }
}

fn get_username(uid: u32) -> Option<String> {
    // Read /etc/passwd to find username for uid
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(line_uid) = parts[2].parse::<u32>() {
                    if line_uid == uid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }
    None
}
