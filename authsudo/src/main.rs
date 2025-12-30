//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required (or requests confirmation via authd)
//! 4. exec() the target command as root or specified user (-u)

use authd_policy::{CallerInfo, PolicyDecision, PolicyEngine, username_from_uid};
use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, wayland_env};
use pam::Client as PamClient;
use peercred_ipc::Client as IpcClient;
use std::collections::HashMap;
use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

/// Arguments that bypass auth (harmless info commands)
const BYPASS_ARGS: &[&str] = &["--help", "-h", "--version", "-V"];

/// Target user for command execution
struct TargetUser {
    uid: u32,
    gid: u32,
    name: Option<String>,
}

impl TargetUser {
    fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            name: Some("root".to_string()),
        }
    }

    fn from_spec(spec: &str) -> Option<Self> {
        // Support #uid format
        if let Some(uid_str) = spec.strip_prefix('#') {
            let uid: u32 = uid_str.parse().ok()?;
            // Get primary group and name for this UID
            unsafe {
                let pwd = libc::getpwuid(uid);
                if pwd.is_null() {
                    // No passwd entry, use uid as gid, no name
                    return Some(Self {
                        uid,
                        gid: uid,
                        name: None,
                    });
                }
                let name = std::ffi::CStr::from_ptr((*pwd).pw_name)
                    .to_string_lossy()
                    .into_owned();
                return Some(Self {
                    uid,
                    gid: (*pwd).pw_gid,
                    name: Some(name),
                });
            }
        }

        // Username lookup
        unsafe {
            let c_name = std::ffi::CString::new(spec).ok()?;
            let pwd = libc::getpwnam(c_name.as_ptr());
            if pwd.is_null() {
                return None;
            }
            Some(Self {
                uid: (*pwd).pw_uid,
                gid: (*pwd).pw_gid,
                name: Some(spec.to_string()),
            })
        }
    }
}

fn main() {
    // Get real UID (who invoked us, not effective UID which is root)
    let real_uid = unsafe { libc::getuid() };

    // Parse arguments
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: authsudo [-u user] <command> [args...]");
        process::exit(1);
    }

    // Parse -u flag
    let (target_user, args) = parse_user_flag(&args);

    if args.is_empty() {
        eprintln!("usage: authsudo [-u user] <command> [args...]");
        process::exit(1);
    }

    let target = PathBuf::from(&args[0]);
    let target_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    // Check for bypass args (--help, --version, etc.)
    let has_bypass_arg = target_args.iter().any(|a| BYPASS_ARGS.contains(a));

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

    // Get caller ancestors for trusted caller bypass
    let caller_info = get_caller_info();
    let callers: Vec<CallerInfo> = caller_info
        .iter()
        .map(|c| CallerInfo {
            exe: c.exe.as_path(),
            cmdline_path: c.cmdline_path.as_deref(),
        })
        .collect();

    // Check policy (skip if bypass arg present)
    let decision = if has_bypass_arg {
        PolicyDecision::AllowImmediate
    } else {
        engine.check_with_callers(&target, real_uid, &callers)
    };

    match decision {
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

    // Set target user (we're setuid root, so we can switch to any user)
    // Order matters: initgroups/setgid before setuid (can't change groups after dropping root)
    unsafe {
        if let Some(ref name) = target_user.name {
            let c_name = std::ffi::CString::new(name.as_str()).unwrap();
            libc::initgroups(c_name.as_ptr(), target_user.gid);
        } else {
            // No username available, just clear supplementary groups
            libc::setgroups(0, std::ptr::null());
        }
        libc::setgid(target_user.gid);
        libc::setuid(target_user.uid);
    }

    // exec the target - this replaces our process
    let err = Command::new(&target).args(&target_args).exec();

    // If we get here, exec failed
    eprintln!("authsudo: failed to execute {}: {}", target.display(), err);
    process::exit(126);
}

/// Info about a caller process (local version with owned data)
struct ProcessInfo {
    exe: PathBuf,
    /// Resolved path of cmdline arg0 (for scripts run via interpreters)
    cmdline_path: Option<PathBuf>,
}

/// Resolve cmdline arg0 to a canonical path
fn resolve_cmdline_path(arg0: &str, pid: i32) -> Option<PathBuf> {
    if arg0.is_empty() {
        return None;
    }

    let path = Path::new(arg0);

    // If absolute, canonicalize directly
    if path.is_absolute() {
        return std::fs::canonicalize(path).ok();
    }

    // Get process's PATH from its environment
    let environ = std::fs::read(format!("/proc/{}/environ", pid)).ok()?;
    let path_var = environ.split(|&b| b == 0).find_map(|entry| {
        let entry = String::from_utf8_lossy(entry);
        entry.strip_prefix("PATH=").map(|p| p.to_string())
    })?;

    // Search PATH for the command
    for dir in path_var.split(':') {
        let full = PathBuf::from(dir).join(arg0);
        if let Ok(resolved) = std::fs::canonicalize(&full) {
            return Some(resolved);
        }
    }

    None
}

/// Get caller info (walk up process tree to find trusted callers)
fn get_caller_info() -> Vec<ProcessInfo> {
    let mut callers = Vec::new();
    let mut pid = unsafe { libc::getppid() } as i32;

    // Walk up to 10 ancestors (avoid infinite loops)
    for _ in 0..10 {
        if pid <= 1 {
            break;
        }

        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).unwrap_or_default();

        // Get cmdline arg0 and resolve to full path (for scripts run via interpreter)
        let cmdline_path = std::fs::read(format!("/proc/{}/cmdline", pid))
            .ok()
            .and_then(|bytes| {
                bytes.split(|&b| b == 0).next().and_then(|arg0| {
                    let arg0_str = String::from_utf8_lossy(arg0);
                    resolve_cmdline_path(&arg0_str, pid)
                })
            });

        if !exe.as_os_str().is_empty() || cmdline_path.is_some() {
            callers.push(ProcessInfo { exe, cmdline_path });
        }

        // Get parent's parent
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(stat) = std::fs::read_to_string(&stat_path) {
            // Format: pid (comm) state ppid ...
            // Find the closing paren then split
            if let Some(paren_end) = stat.rfind(')') {
                let rest = &stat[paren_end + 2..]; // skip ") "
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(ppid_str) = fields.get(1) {
                    // state is [0], ppid is [1]
                    if let Ok(ppid) = ppid_str.parse::<i32>() {
                        pid = ppid;
                        continue;
                    }
                }
            }
        }
        break;
    }

    callers
}

/// Resolve a command to its absolute path
fn resolve_path(cmd: &Path) -> Option<PathBuf> {
    if cmd.is_absolute() {
        if cmd.exists() {
            return Some(cmd.to_path_buf());
        }
        return None;
    }

    // Relative path (contains / but not absolute) - resolve against cwd
    if cmd.components().count() > 1 {
        if let Ok(cwd) = env::current_dir() {
            let full = cwd.join(cmd);
            if full.exists() {
                return std::fs::canonicalize(&full).ok();
            }
        }
        return None;
    }

    // Search PATH for simple command names
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

    match IpcClient::call(SOCKET_PATH, &request) {
        Ok(AuthResponse::Success { .. }) => true,
        Ok(AuthResponse::Denied { reason }) => {
            eprintln!("authsudo: {}", reason);
            false
        }
        Err(e) => {
            eprintln!("authsudo: cannot connect to authd: {}", e);
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
    let password =
        match rpassword::prompt_password(format!("[authsudo] password for {}: ", username)) {
            Ok(p) => p,
            Err(_) => return false,
        };

    // PAM authentication
    let Ok(mut client) = PamClient::with_password("authd") else {
        return false;
    };

    client
        .conversation_mut()
        .set_credentials(username, &password);

    client.authenticate().is_ok()
}

/// Parse -u/--user flag from arguments
fn parse_user_flag(args: &[String]) -> (TargetUser, Vec<String>) {
    let mut iter = args.iter().peekable();
    let mut target_user = TargetUser::root();
    let mut remaining = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "-u" || arg == "--user" {
            if let Some(user_spec) = iter.next() {
                match TargetUser::from_spec(user_spec) {
                    Some(user) => target_user = user,
                    None => {
                        eprintln!("authsudo: unknown user: {}", user_spec);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("authsudo: -u requires an argument");
                process::exit(1);
            }
        } else if let Some(user_spec) = arg.strip_prefix("-u") {
            // Handle -uUSER format (no space)
            match TargetUser::from_spec(user_spec) {
                Some(user) => target_user = user,
                None => {
                    eprintln!("authsudo: unknown user: {}", user_spec);
                    process::exit(1);
                }
            }
        } else {
            // First non-flag argument starts the command
            remaining.push(arg.clone());
            remaining.extend(iter.cloned());
            break;
        }
    }

    (target_user, remaining)
}
