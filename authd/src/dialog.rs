//! Confirmation dialog for authd using ext-session-lock
//!
//! Forks a child process, drops privileges, sets environment, and execs
//! the authd-dialog binary which shows a secure session-lock confirmation.

use authd_protocol::CallerInfo;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::PathBuf;

/// Result of showing the confirmation dialog
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DialogResult {
    Confirmed,
    Denied,
    Error,
}

/// Show a confirmation dialog in a forked child process
///
/// The child drops privileges to the caller's UID/GID, sets Wayland env vars,
/// execs authd-dialog which locks the session and shows confirmation dialog.
pub fn show_confirmation_dialog(
    caller: &CallerInfo,
    target: &PathBuf,
    args: &[String],
    env: &HashMap<String, String>,
) -> DialogResult {
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            tracing::error!("fork failed");
            DialogResult::Error
        }
        0 => {
            // Child process
            run_dialog_child(caller, target, args, env);
        }
        child_pid => {
            // Parent: wait for child
            let mut status: libc::c_int = 0;
            let result = unsafe { libc::waitpid(child_pid, &mut status, 0) };

            if result == -1 {
                tracing::error!("waitpid failed");
                return DialogResult::Error;
            }

            if libc::WIFEXITED(status) {
                let exit_code = libc::WEXITSTATUS(status);
                if exit_code == 0 {
                    DialogResult::Confirmed
                } else {
                    DialogResult::Denied
                }
            } else {
                DialogResult::Error
            }
        }
    }
}

fn run_dialog_child(
    caller: &CallerInfo,
    target: &PathBuf,
    args: &[String],
    env: &HashMap<String, String>,
) -> ! {
    // Start new session
    unsafe { libc::setsid() };

    // Set Wayland environment variables
    // SAFETY: forked child, no other threads
    for (key, val) in env {
        unsafe { std::env::set_var(key, val) };
    }

    // Set HOME to user's home directory (for shader cache etc)
    let home = format!("/home/{}", get_username(caller.uid).unwrap_or_else(|| "nobody".into()));
    unsafe { std::env::set_var("HOME", &home) };
    unsafe { std::env::set_var("USER", get_username(caller.uid).unwrap_or_else(|| "nobody".into())) };

    // Drop privileges (GID first, then UID)
    unsafe {
        if libc::setgid(caller.gid) != 0 {
            eprintln!("authd: setgid({}) failed", caller.gid);
            std::process::exit(1);
        }
        if libc::setuid(caller.uid) != 0 {
            eprintln!("authd: setuid({}) failed", caller.uid);
            std::process::exit(1);
        }
    }

    // Find authd-dialog binary (same directory as authd)
    let dialog_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("authd-dialog")))
        .unwrap_or_else(|| PathBuf::from("/usr/bin/authd-dialog"));

    // Build command string for dialog
    let command = if args.is_empty() {
        target.to_string_lossy().to_string()
    } else {
        format!("{} {}", target.display(), args.join(" "))
    };

    // Exec the dialog binary
    let c_prog = CString::new(dialog_bin.to_string_lossy().as_bytes()).unwrap();
    let c_arg0 = c_prog.clone();
    let c_arg1 = CString::new(command.as_bytes()).unwrap();
    let c_args: Vec<*const libc::c_char> = vec![
        c_arg0.as_ptr(),
        c_arg1.as_ptr(),
        std::ptr::null(),
    ];

    unsafe {
        libc::execv(c_prog.as_ptr(), c_args.as_ptr());
    }

    eprintln!("authd: exec {:?} failed: {}", dialog_bin, std::io::Error::last_os_error());
    std::process::exit(1);
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
