//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required
//! 4. exec() the target command

use authd_policy::{username_from_uid, PolicyDecision, PolicyEngine};
use pam::Client;
use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

fn main() {
    // Get real UID (who invoked us, not effective UID which is root)
    let real_uid = unsafe { libc::getuid() };

    // Parse arguments
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: authsudo <command> [args...]");
        process::exit(1);
    }

    let target = PathBuf::from(&args[0]);
    let target_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    // Resolve to absolute path
    let target = resolve_path(&target).unwrap_or_else(|| {
        eprintln!("authsudo: command not found: {}", args[0]);
        process::exit(127);
    });

    // Load policies
    let mut engine = PolicyEngine::new();
    if let Err(e) = engine.load() {
        eprintln!("authsudo: failed to load policies: {}", e);
        process::exit(1);
    }

    // Get caller (parent process) for trusted caller bypass
    let caller_exe = get_caller_exe();

    // Check policy
    match engine.check_with_caller(&target, real_uid, caller_exe.as_deref()) {
        PolicyDecision::AllowImmediate | PolicyDecision::AllowWithConfirm => {
            // Allowed without auth (CLI has no dialog, treat confirm as allow)
        }
        PolicyDecision::RequireAuth => {
            // Need password authentication
            let username = username_from_uid(real_uid).unwrap_or_else(|| {
                eprintln!("authsudo: unknown user");
                process::exit(1);
            });

            if !authenticate_user(&username) {
                eprintln!("authsudo: authentication failed");
                process::exit(1);
            }
        }
        PolicyDecision::Denied(reason) => {
            eprintln!("authsudo: {}", reason);
            process::exit(1);
        }
        PolicyDecision::Unknown => {
            eprintln!("authsudo: no policy for {}", target.display());
            process::exit(1);
        }
    }

    // Drop back to root (we're setuid root, effective UID is already 0)
    // Set real UID to 0 as well for the exec
    unsafe {
        libc::setgid(0);
        libc::setuid(0);
    }

    // exec the target - this replaces our process
    let err = Command::new(&target).args(&target_args).exec();

    // If we get here, exec failed
    eprintln!("authsudo: failed to execute {}: {}", target.display(), err);
    process::exit(126);
}

/// Get the caller's executable path (parent process)
fn get_caller_exe() -> Option<PathBuf> {
    let ppid = unsafe { libc::getppid() };
    std::fs::read_link(format!("/proc/{}/exe", ppid)).ok()
}

/// Resolve a command to its absolute path
fn resolve_path(cmd: &Path) -> Option<PathBuf> {
    if cmd.is_absolute() {
        if cmd.exists() {
            return Some(cmd.to_path_buf());
        }
        return None;
    }

    // Search PATH
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let full = PathBuf::from(dir).join(cmd);
            if full.exists() {
                return Some(full);
            }
        }
    }

    None
}

/// Authenticate user via PAM
fn authenticate_user(username: &str) -> bool {
    // Read password from terminal
    let password = match rpassword::prompt_password(format!("[authsudo] password for {}: ", username)) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // PAM authentication
    let Ok(mut client) = Client::with_password("authd") else {
        return false;
    };

    client
        .conversation_mut()
        .set_credentials(username, &password);

    client.authenticate().is_ok()
}
