//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required (or requests confirmation via authd)
//! 4. exec() the target command

use authd_policy::{username_from_uid, PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use pam::Client;
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
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
        PolicyDecision::AllowImmediate => {
            // Allowed without any interaction
        }
        PolicyDecision::AllowWithConfirm => {
            // Request confirmation from authd (shows session-lock dialog)
            if !request_confirmation(&target, &target_args) {
                eprintln!("authsudo: authorization denied");
                process::exit(1);
            }
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

/// Request confirmation from authd via session-lock dialog
fn request_confirmation(target: &Path, args: &[&str]) -> bool {
    let request = AuthRequest {
        target: target.to_path_buf(),
        args: args.iter().map(|s| s.to_string()).collect(),
        env: collect_wayland_env(),
        password: String::new(),
        confirm_only: true,
    };

    let mut stream = match UnixStream::connect(SOCKET_PATH) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("authsudo: cannot connect to authd: {}", e);
            return false;
        }
    };

    let data = match rmp_serde::to_vec(&request) {
        Ok(d) => d,
        Err(_) => return false,
    };

    if stream.write_all(&data).is_err() {
        return false;
    }

    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };

    match rmp_serde::from_slice::<AuthResponse>(&buf[..n]) {
        Ok(AuthResponse::Success { .. }) => true,
        Ok(AuthResponse::Denied { reason }) => {
            eprintln!("authsudo: {}", reason);
            false
        }
        _ => false,
    }
}

/// Collect Wayland environment variables
fn collect_wayland_env() -> HashMap<String, String> {
    wayland_env()
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|val| (key.to_string(), val)))
        .collect()
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
