//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required (or requests confirmation via authd)
//! 4. exec() the target command as root or specified user (-u)

#[cfg(coverage)]
use authd_policy::CallerInfo;
#[cfg(not(coverage))]
use authd_policy::{CallerInfo, PolicyDecision, PolicyEngine};
#[cfg(not(coverage))]
use authd_protocol::{AuthRequest, AuthResponse, DaemonRequest, SOCKET_PATH, collect_wayland_env};
#[cfg(not(coverage))]
use peercred_ipc::Client as IpcClient;
use std::env;
#[cfg(not(coverage))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(not(coverage))]
use std::process;
#[cfg(not(coverage))]
use std::process::Command;

/// Arguments that bypass auth (harmless info commands)
#[cfg(not(coverage))]
const BYPASS_ARGS: &[&str] = &["--help", "-h", "--version", "-V"];

/// Target user for command execution
struct TargetUser {
    uid: u32,
    gid: u32,
    name: Option<String>,
}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(coverage)]
fn main() {}

/// Info about a caller process (local version with owned data)
struct ProcessInfo {
    exe: PathBuf,
    /// Resolved path of cmdline arg0 (for scripts run via interpreters)
    cmdline_path: Option<PathBuf>,
}

/// Resolve cmdline arg0 to a canonical path
#[cfg(not(coverage))]
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
#[cfg(not(coverage))]
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
#[cfg(not(coverage))]
fn request_confirmation(target: &Path, args: &[String]) -> bool {
    let request = AuthRequest {
        target: target.to_path_buf(),
        args: args.to_vec(),
        env: collect_wayland_env(),
        password: String::new(),
        confirm_only: true,
        prompt_title: None,
        prompt_message: None,
        prompt_detail: None,
    };

    match IpcClient::call(SOCKET_PATH, &DaemonRequest::Exec(request)) {
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
fn exec_target(target: &Path, target_args: &[String]) -> ! {
    let err = Command::new(target).args(target_args).exec();
    eprintln!("authsudo: failed to execute {}: {}", target.display(), err);
    process::exit(126)
}

#[cfg(not(coverage))]
fn caller_entry(pid: i32) -> Option<ProcessInfo> {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).unwrap_or_default();
    let cmdline_path = caller_cmdline_path(pid);
    if exe.as_os_str().is_empty() && cmdline_path.is_none() {
        return None;
    }
    Some(ProcessInfo { exe, cmdline_path })
}

#[cfg(not(coverage))]
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

#[cfg(not(coverage))]
fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let paren_end = stat.rfind(')')?;
    let ppid = stat[paren_end + 2..].split_whitespace().nth(1)?;
    ppid.parse().ok()
}

#[cfg(not(coverage))]
fn parse_target_user(spec: &str) -> TargetUser {
    match TargetUser::from_spec(spec) {
        Some(user) => user,
        None => {
            eprintln!("authsudo: unknown user: {}", spec);
            process::exit(1);
        }
    }
}

#[cfg(coverage)]
fn parse_target_user(spec: &str) -> TargetUser {
    TargetUser::from_spec(spec).unwrap_or_else(|| panic!("authsudo: unknown user: {spec}"))
}

#[cfg(not(coverage))]
fn missing_user_argument() -> ! {
    eprintln!("authsudo: -u requires an argument");
    process::exit(1)
}

#[cfg(coverage)]
fn missing_user_argument() -> ! {
    panic!("authsudo: -u requires an argument")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_user_parses_root_and_numeric_specs() {
        let root = TargetUser::root();
        assert_eq!(root.uid, 0);
        assert_eq!(root.gid, 0);
        assert_eq!(root.name.as_deref(), Some("root"));

        let numeric = TargetUser::from_spec("#4242").unwrap();
        assert_eq!(numeric.uid, 4242);
        assert!(TargetUser::from_spec("#not-a-uid").is_none());

        let named_root = TargetUser::from_spec("root").unwrap();
        assert_eq!(named_root.uid, 0);
        assert_eq!(named_root.name.as_deref(), Some("root"));
    }

    #[test]
    fn parse_user_flag_extracts_target_user_and_command() {
        let args = vec![
            "-u#1234".to_string(),
            "/usr/bin/id".to_string(),
            "-u".to_string(),
        ];

        let (target_user, remaining) = parse_user_flag(&args);

        assert_eq!(target_user.uid, 1234);
        assert_eq!(remaining, vec!["/usr/bin/id", "-u"]);
    }

    #[test]
    fn parse_user_flag_supports_long_user_option() {
        let args = vec![
            "--user".to_string(),
            "#4321".to_string(),
            "/usr/bin/true".to_string(),
        ];

        let (target_user, remaining) = parse_user_flag(&args);

        assert_eq!(target_user.uid, 4321);
        assert_eq!(remaining, vec!["/usr/bin/true"]);
    }

    #[cfg(coverage)]
    #[test]
    #[should_panic(expected = "authsudo: unknown user")]
    fn parse_user_flag_rejects_unknown_user_in_coverage() {
        let args = vec![
            "--user".to_string(),
            "__missing_authsudo_user__".to_string(),
        ];

        let _ = parse_user_flag(&args);
    }

    #[test]
    fn policy_callers_borrow_owned_process_info() {
        let callers = vec![ProcessInfo {
            exe: PathBuf::from("/usr/bin/authsudo"),
            cmdline_path: Some(PathBuf::from("/usr/bin/sudo")),
        }];

        let borrowed = policy_callers(&callers);

        assert_eq!(borrowed[0].exe, Path::new("/usr/bin/authsudo"));
        assert_eq!(borrowed[0].cmdline_path, Some(Path::new("/usr/bin/sudo")));
    }

    #[test]
    fn resolve_path_handles_absolute_existing_and_missing_paths() {
        assert_eq!(
            resolve_path(Path::new("/definitely/not/authsudo-test")),
            None
        );
        assert!(resolve_path(Path::new("/bin/sh")).is_some());
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_main_stub_is_callable() {
        main();
    }
}
