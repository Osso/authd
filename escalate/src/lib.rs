//! Helper for auto-escalating privileges via authsudo.
//!
//! # Example
//!
//! ```no_run
//! use authd_escalate::ensure_root;
//!
//! fn main() {
//!     // Will re-exec via authsudo if not already root
//!     ensure_root().expect("Need root privileges");
//!
//!     // Now running as root
//!     println!("Running as root!");
//! }
//! ```

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use nix::unistd::{Uid, User};

/// Error type for escalation failures.
#[derive(Debug)]
pub enum Error {
    /// authsudo binary not found in PATH
    AuthsudoNotFound,
    /// exec() syscall failed
    ExecFailed(io::Error),
    /// User lookup failed
    UserNotFound(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AuthsudoNotFound => {
                write!(f, "This operation requires elevated privileges. Install authsudo or run with sudo.")
            }
            Error::ExecFailed(e) => write!(f, "Failed to exec authsudo: {}", e),
            Error::UserNotFound(name) => write!(f, "User not found: {}", name),
        }
    }
}

impl std::error::Error for Error {}

/// Ensure we're running as root. If not, re-exec via authsudo.
///
/// Returns `Ok(())` if already root. Otherwise attempts to re-exec
/// through authsudo. If authsudo is not available, returns an error.
///
/// # Note
/// This function only returns on error or if already root.
/// On successful escalation, the process is replaced via exec().
pub fn ensure_root() -> Result<(), Error> {
    ensure_user_id(Uid::from_raw(0))
}

/// Ensure we're running as a specific user. If not, re-exec via authsudo.
///
/// Returns `Ok(())` if already running as the target user. Otherwise
/// attempts to re-exec through authsudo with `-u <user>`.
pub fn ensure_user(username: &str) -> Result<(), Error> {
    let user = User::from_name(username)
        .ok()
        .flatten()
        .ok_or_else(|| Error::UserNotFound(username.to_string()))?;

    ensure_user_id(user.uid)
}

/// Ensure we're running as a specific UID. If not, re-exec via authsudo.
pub fn ensure_user_id(target_uid: Uid) -> Result<(), Error> {
    if Uid::effective() == target_uid {
        return Ok(());
    }

    let authsudo = which("authsudo").ok_or(Error::AuthsudoNotFound)?;

    // Use absolute path to current executable to prevent TOCTOU
    let exe = std::env::current_exe().map_err(|e| Error::ExecFailed(e))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    let mut cmd = Command::new(&authsudo);

    // If not root, add -u flag
    if target_uid != Uid::from_raw(0) {
        // Look up username from uid
        if let Some(user) = User::from_uid(target_uid).ok().flatten() {
            cmd.arg("-u").arg(user.name);
        } else {
            cmd.arg("-u").arg(format!("#{}", target_uid));
        }
    }

    cmd.arg(&exe).args(&args);

    let err = cmd.exec();
    Err(Error::ExecFailed(err))
}

/// Check if authsudo is available in PATH.
pub fn is_available() -> bool {
    which("authsudo").is_some()
}

fn which(binary: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let path = dir.join(binary);
            if let Ok(meta) = path.metadata() {
                // Check it's a file and executable
                if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return Some(path);
                }
            }
            None
        })
    })
}
