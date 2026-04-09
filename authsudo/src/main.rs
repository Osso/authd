//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required (or requests confirmation via authd)
//! 4. exec() the target command as root or specified user (-u)

use authd_policy::{CallerInfo, PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH, collect_wayland_env};
use peercred_ipc::Client as IpcClient;
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

struct Invocation {
    target_user: TargetUser,
    target: PathBuf,
    target_args: Vec<String>,
    has_bypass_arg: bool,
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
    let real_uid = unsafe { libc::getuid() };
    let invocation = parse_invocation();
    let engine = load_policy_engine();
    let caller_info = get_caller_info();
    let callers = policy_callers(&caller_info);
    enforce_policy(&engine, &invocation, real_uid, &callers);
    switch_to_target_user(&invocation.target_user);
    exec_target(&invocation.target, &invocation.target_args);
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
    for _ in 0..10 {
        if pid <= 1 {
            break;
        }
        if let Some(caller) = caller_entry(pid) {
            callers.push(caller);
        }
        let Some(parent_pid) = parent_pid(pid) else {
            break;
        };
        pid = parent_pid;
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
fn request_confirmation(target: &Path, args: &[String]) -> bool {
    let request = AuthRequest {
        target: target.to_path_buf(),
        args: args.to_vec(),
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

/// Parse -u/--user flag from arguments
fn parse_user_flag(args: &[String]) -> (TargetUser, Vec<String>) {
    let mut iter = args.iter().peekable();
    let mut target_user = TargetUser::root();
    let mut remaining = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "-u" || arg == "--user" {
            let user_spec = iter.next().unwrap_or_else(|| missing_user_argument());
            target_user = parse_target_user(user_spec);
            continue;
        }

        if let Some(user_spec) = arg.strip_prefix("-u") {
            target_user = parse_target_user(user_spec);
            continue;
        }

        remaining.push(arg.clone());
        remaining.extend(iter.cloned());
        break;
    }

    (target_user, remaining)
}

fn parse_invocation() -> Invocation {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: authsudo [-u user] <command> [args...]");
        process::exit(1);
    }

    let (target_user, args) = parse_user_flag(&args);
    if args.is_empty() {
        eprintln!("usage: authsudo [-u user] <command> [args...]");
        process::exit(1);
    }

    let target_args: Vec<String> = args.iter().skip(1).cloned().collect();
    let target = resolve_path(Path::new(&args[0])).unwrap_or_else(|| {
        eprintln!("authsudo: command not found: {}", args[0]);
        process::exit(127);
    });

    Invocation {
        target_user,
        target,
        has_bypass_arg: target_args
            .iter()
            .any(|arg| BYPASS_ARGS.contains(&arg.as_str())),
        target_args,
    }
}

fn load_policy_engine() -> PolicyEngine {
    let mut engine = PolicyEngine::new();
    if let Err(error) = engine.load() {
        eprintln!("authsudo: failed to load policies: {}", error);
        process::exit(1);
    }
    engine
}

fn policy_callers(callers: &[ProcessInfo]) -> Vec<CallerInfo<'_>> {
    callers
        .iter()
        .map(|caller| CallerInfo {
            exe: caller.exe.as_path(),
            cmdline_path: caller.cmdline_path.as_deref(),
        })
        .collect()
}

fn enforce_policy(
    engine: &PolicyEngine,
    invocation: &Invocation,
    real_uid: u32,
    callers: &[CallerInfo<'_>],
) {
    let decision = if invocation.has_bypass_arg {
        PolicyDecision::AllowImmediate
    } else {
        engine.check_with_callers(&invocation.target, real_uid, callers)
    };

    match decision {
        PolicyDecision::AllowImmediate => {}
        PolicyDecision::AllowWithConfirm => {
            if !request_confirmation(&invocation.target, &invocation.target_args) {
                eprintln!("authsudo: authorization denied");
                process::exit(1);
            }
        }
        PolicyDecision::Denied(reason) => {
            eprintln!("authsudo: {}", reason);
            process::exit(1);
        }
        PolicyDecision::Unknown => {
            eprintln!("authsudo: no policy for {}", invocation.target.display());
            process::exit(1);
        }
    }
}

fn switch_to_target_user(target_user: &TargetUser) {
    unsafe {
        if let Some(name) = &target_user.name {
            let c_name = std::ffi::CString::new(name.as_str()).unwrap();
            libc::initgroups(c_name.as_ptr(), target_user.gid);
        } else {
            libc::setgroups(0, std::ptr::null());
        }
        libc::setgid(target_user.gid);
        libc::setuid(target_user.uid);
    }
}

fn exec_target(target: &Path, target_args: &[String]) -> ! {
    let err = Command::new(target).args(target_args).exec();
    eprintln!("authsudo: failed to execute {}: {}", target.display(), err);
    process::exit(126)
}

fn caller_entry(pid: i32) -> Option<ProcessInfo> {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).unwrap_or_default();
    let cmdline_path = caller_cmdline_path(pid);
    if exe.as_os_str().is_empty() && cmdline_path.is_none() {
        return None;
    }
    Some(ProcessInfo { exe, cmdline_path })
}

fn caller_cmdline_path(pid: i32) -> Option<PathBuf> {
    std::fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .and_then(|bytes| {
            bytes
                .split(|&byte| byte == 0)
                .next()
                .map(|arg0| arg0.to_vec())
        })
        .and_then(|arg0| String::from_utf8(arg0).ok())
        .and_then(|arg0| resolve_cmdline_path(&arg0, pid))
}

fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let paren_end = stat.rfind(')')?;
    let ppid = stat[paren_end + 2..].split_whitespace().nth(1)?;
    ppid.parse().ok()
}

fn parse_target_user(spec: &str) -> TargetUser {
    match TargetUser::from_spec(spec) {
        Some(user) => user,
        None => {
            eprintln!("authsudo: unknown user: {}", spec);
            process::exit(1);
        }
    }
}

fn missing_user_argument() -> ! {
    eprintln!("authsudo: -u requires an argument");
    process::exit(1)
}
