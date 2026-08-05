use authd_protocol::{
    AgentExecutableRule, AgentTerminalSession, ConfirmSessionRequest, ConfirmSessionTarget,
    wayland_env,
};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

const MAX_AGENT_SESSION_ANCESTORS: usize = 8;
const EXECUTABLE_PERMISSION_BITS: u32 = 0o111;
const GROUP_OR_WORLD_WRITE_BITS: u32 = 0o022;
const PROC_STAT_PARENT_PID_INDEX: usize = 1;
const PROC_STAT_SESSION_ID_INDEX: usize = 3;
const PROC_STAT_TTY_DEVICE_INDEX: usize = 4;
const PROC_STAT_START_TIME_INDEX: usize = 19;
const REQUIRED_SESSION_ENVIRONMENT: [&str; 2] = ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"];

#[derive(Debug)]
pub struct ValidatedSession {
    pub uid: u32,
    pub gid: u32,
    pub env: HashMap<String, String>,
}

#[derive(Debug)]
struct ValidatedTargetProcess {
    process_dir: PathBuf,
    initial_start_time: u64,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
struct ProcessStat {
    parent_pid: u32,
    session_id: u32,
    tty_device: i64,
    start_time: u64,
}

#[derive(Debug)]
struct ProcessExecutable {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

struct ValidatedSessionTarget {
    process: ValidatedTargetProcess,
    terminal: Option<ValidatedTargetProcess>,
    env: HashMap<String, String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionValidationError {
    #[error("target process is unavailable")]
    ProcessUnavailable,
    #[error("target process start time changed")]
    StartTimeMismatch,
    #[error("target process uid does not match requested uid")]
    UidMismatch,
    #[error("target process does not match the agent executable rule")]
    AgentExecutableMismatch,
    #[error("target process executable identity does not match the request")]
    AgentExecutableIdentityMismatch,
    #[error("configured agent executable is not private and executable")]
    AgentExecutablePermissions,
    #[error("configured agent executable owner does not match target uid")]
    AgentExecutableOwnerMismatch,
    #[error("configured agent has no launchers")]
    AgentLaunchersMissing,
    #[error("configured agent requires a verified terminal origin")]
    AgentTerminalRequired,
    #[error("Pi agent target must not claim a terminal origin")]
    AgentTerminalUnexpected,
    #[error("agent process does not belong to the claimed terminal session")]
    AgentTerminalSessionMismatch,
    #[error("terminal target is not the session leader")]
    TerminalNotSessionLeader,
    #[error("terminal target has no controlling tty")]
    TerminalNoControllingTty,
    #[error("terminal target controlling tty does not match claimed tty")]
    TerminalTtyMismatch,
    #[error("target process has no reachable Wayland session")]
    MissingSessionEnvironment,
    #[error("runtime directory is not owned by target uid")]
    RuntimeDirectoryOwnerMismatch,
}

pub fn validate_confirm_session(
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSession, SessionValidationError> {
    validate_confirm_session_at(Path::new("/proc"), request)
}

fn validate_confirm_session_at(
    proc_root: &Path,
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSession, SessionValidationError> {
    let validated = read_validated_session_target(proc_root, request)?;
    ensure_process_start_time_unchanged(
        &validated.process.process_dir,
        validated.process.initial_start_time,
    )?;
    if let Some(terminal) = &validated.terminal {
        ensure_process_start_time_unchanged(&terminal.process_dir, terminal.initial_start_time)?;
    }
    Ok(ValidatedSession {
        uid: validated.process.uid,
        gid: validated.process.gid,
        env: validated.env,
    })
}

fn read_validated_session_target(
    proc_root: &Path,
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSessionTarget, SessionValidationError> {
    match &request.target {
        ConfirmSessionTarget::Agent { .. } => {
            read_validated_agent_session_target(proc_root, request)
        }
        ConfirmSessionTarget::Terminal { .. } => {
            read_validated_terminal_session_target(proc_root, request)
        }
    }
}

fn read_validated_agent_session_target(
    proc_root: &Path,
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSessionTarget, SessionValidationError> {
    let ConfirmSessionTarget::Agent {
        executable_rule,
        pid,
        start_time,
        executable_device,
        executable_inode,
        terminal,
        ..
    } = &request.target
    else {
        unreachable!("agent target was selected by the caller")
    };
    let (process, terminal) = read_and_validate_agent_target_process(
        proc_root,
        *pid,
        *start_time,
        *executable_device,
        *executable_inode,
        executable_rule,
        terminal.as_ref(),
        request.target_uid,
    )?;
    let env = read_agent_session_environment(proc_root, *pid, process.uid, executable_rule)?;
    Ok(ValidatedSessionTarget {
        process,
        terminal,
        env,
    })
}

fn read_validated_terminal_session_target(
    proc_root: &Path,
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSessionTarget, SessionValidationError> {
    let ConfirmSessionTarget::Terminal {
        leader_pid,
        leader_start_time,
        tty_device,
    } = &request.target
    else {
        unreachable!("terminal target was selected by the caller")
    };
    let process = read_and_validate_terminal_target_process(
        proc_root,
        *leader_pid,
        *leader_start_time,
        *tty_device,
        request.target_uid,
    )?;
    let env = read_terminal_session_environment(&process.process_dir, process.uid)?;
    Ok(ValidatedSessionTarget {
        process,
        terminal: None,
        env,
    })
}

fn read_and_validate_agent_target_process(
    proc_root: &Path,
    pid: u32,
    start_time: u64,
    executable_device: u64,
    executable_inode: u64,
    executable_rule: &AgentExecutableRule,
    terminal: Option<&AgentTerminalSession>,
    target_uid: u32,
) -> Result<(ValidatedTargetProcess, Option<ValidatedTargetProcess>), SessionValidationError> {
    let process_dir = proc_root.join(pid.to_string());
    let stat = read_process_stat(&process_dir)?;
    if stat.start_time != start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }
    let (uid, gid) = read_process_ids(&process_dir)?;
    if uid != target_uid {
        return Err(SessionValidationError::UidMismatch);
    }
    let executable = read_process_executable(&process_dir)?;
    validate_agent_executable_rule(&executable, executable_rule, target_uid)?;
    if executable.device != executable_device || executable.inode != executable_inode {
        return Err(SessionValidationError::AgentExecutableIdentityMismatch);
    }
    let terminal =
        read_and_validate_agent_terminal(proc_root, &stat, executable_rule, terminal, target_uid)?;
    Ok((
        ValidatedTargetProcess {
            process_dir,
            initial_start_time: stat.start_time,
            uid,
            gid,
        },
        terminal,
    ))
}

fn read_and_validate_agent_terminal(
    proc_root: &Path,
    agent_stat: &ProcessStat,
    executable_rule: &AgentExecutableRule,
    terminal: Option<&AgentTerminalSession>,
    target_uid: u32,
) -> Result<Option<ValidatedTargetProcess>, SessionValidationError> {
    match (executable_rule, terminal) {
        (AgentExecutableRule::Pi, None) => Ok(None),
        (AgentExecutableRule::Pi, Some(_)) => Err(SessionValidationError::AgentTerminalUnexpected),
        (AgentExecutableRule::Pinned { .. }, None) => {
            Err(SessionValidationError::AgentTerminalRequired)
        }
        (AgentExecutableRule::Pinned { .. }, Some(terminal)) => {
            if agent_stat.session_id != terminal.leader_pid
                || agent_stat.tty_device == 0
                || agent_stat.tty_device != terminal.tty_device
            {
                return Err(SessionValidationError::AgentTerminalSessionMismatch);
            }
            read_and_validate_terminal_target_process(
                proc_root,
                terminal.leader_pid,
                terminal.leader_start_time,
                terminal.tty_device,
                target_uid,
            )
            .map(Some)
        }
    }
}

fn read_and_validate_terminal_target_process(
    proc_root: &Path,
    leader_pid: u32,
    leader_start_time: u64,
    tty_device: i64,
    target_uid: u32,
) -> Result<ValidatedTargetProcess, SessionValidationError> {
    let process_dir = proc_root.join(leader_pid.to_string());
    let stat = read_process_stat(&process_dir)?;
    if stat.start_time != leader_start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }

    let (uid, gid) = read_process_ids(&process_dir)?;
    if uid != target_uid {
        return Err(SessionValidationError::UidMismatch);
    }
    if stat.session_id != leader_pid {
        return Err(SessionValidationError::TerminalNotSessionLeader);
    }
    if stat.tty_device == 0 || tty_device == 0 {
        return Err(SessionValidationError::TerminalNoControllingTty);
    }
    if stat.tty_device != tty_device {
        return Err(SessionValidationError::TerminalTtyMismatch);
    }

    Ok(ValidatedTargetProcess {
        process_dir,
        initial_start_time: stat.start_time,
        uid,
        gid,
    })
}

fn ensure_process_start_time_unchanged(
    process_dir: &Path,
    initial_start_time: u64,
) -> Result<(), SessionValidationError> {
    let final_start_time = read_start_time(process_dir)?;
    if final_start_time != initial_start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }
    Ok(())
}

fn read_start_time(process_dir: &Path) -> Result<u64, SessionValidationError> {
    read_process_stat(process_dir).map(|stat| stat.start_time)
}

fn read_process_stat(process_dir: &Path) -> Result<ProcessStat, SessionValidationError> {
    let stat = fs::read_to_string(process_dir.join("stat"))
        .map_err(|_| SessionValidationError::ProcessUnavailable)?;
    parse_process_stat(&stat)
}

fn parse_process_stat(stat: &str) -> Result<ProcessStat, SessionValidationError> {
    let command_end = stat
        .rfind(") ")
        .ok_or(SessionValidationError::ProcessUnavailable)?;
    let fields = stat[command_end + 2..]
        .split_whitespace()
        .collect::<Vec<_>>();
    Ok(ProcessStat {
        parent_pid: parse_process_stat_field(&fields, PROC_STAT_PARENT_PID_INDEX)?,
        session_id: parse_process_stat_field(&fields, PROC_STAT_SESSION_ID_INDEX)?,
        tty_device: parse_process_stat_field(&fields, PROC_STAT_TTY_DEVICE_INDEX)?,
        start_time: parse_process_stat_field(&fields, PROC_STAT_START_TIME_INDEX)?,
    })
}

fn parse_process_stat_field<T>(fields: &[&str], index: usize) -> Result<T, SessionValidationError>
where
    T: FromStr,
{
    fields
        .get(index)
        .and_then(|value| value.parse().ok())
        .ok_or(SessionValidationError::ProcessUnavailable)
}

fn read_terminal_session_environment(
    process_dir: &Path,
    uid: u32,
) -> Result<HashMap<String, String>, SessionValidationError> {
    let env = read_session_environment(process_dir)?;
    validate_runtime_directory_owner(&env, uid)?;
    Ok(env)
}

fn read_agent_session_environment(
    proc_root: &Path,
    agent_pid: u32,
    uid: u32,
    executable_rule: &AgentExecutableRule,
) -> Result<HashMap<String, String>, SessionValidationError> {
    let mut current_pid = agent_pid;
    for _ in 0..MAX_AGENT_SESSION_ANCESTORS {
        let process_dir = proc_root.join(current_pid.to_string());
        if let Some(env) = read_owned_session_environment(&process_dir, uid)? {
            return Ok(env);
        }

        let Some(parent_pid) =
            read_same_uid_agent_parent(proc_root, &process_dir, current_pid, uid, executable_rule)?
        else {
            break;
        };
        current_pid = parent_pid;
    }
    Err(SessionValidationError::MissingSessionEnvironment)
}

fn read_owned_session_environment(
    process_dir: &Path,
    uid: u32,
) -> Result<Option<HashMap<String, String>>, SessionValidationError> {
    match read_session_environment(process_dir) {
        Ok(env) => {
            validate_runtime_directory_owner(&env, uid)?;
            Ok(Some(env))
        }
        Err(SessionValidationError::MissingSessionEnvironment) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_same_uid_agent_parent(
    proc_root: &Path,
    process_dir: &Path,
    current_pid: u32,
    uid: u32,
    executable_rule: &AgentExecutableRule,
) -> Result<Option<u32>, SessionValidationError> {
    let parent_pid = read_process_stat(process_dir)?.parent_pid;
    if parent_pid == 0 || parent_pid == current_pid {
        return Ok(None);
    }

    let parent_dir = proc_root.join(parent_pid.to_string());
    let executable = match read_process_executable(&parent_dir) {
        Ok(executable) => executable,
        Err(SessionValidationError::ProcessUnavailable) => return Ok(None),
        Err(error) => return Err(error),
    };
    match validate_agent_executable_rule(&executable, executable_rule, uid) {
        Ok(()) => {}
        Err(SessionValidationError::AgentExecutableMismatch) => return Ok(None),
        Err(error) => return Err(error),
    }
    let (parent_uid, _) = read_process_ids(&parent_dir)?;
    if parent_uid != uid {
        return Err(SessionValidationError::UidMismatch);
    }
    Ok(Some(parent_pid))
}

fn read_process_executable(
    process_dir: &Path,
) -> Result<ProcessExecutable, SessionValidationError> {
    let exe_link = process_dir.join("exe");
    let path = fs::read_link(&exe_link).map_err(|_| SessionValidationError::ProcessUnavailable)?;
    let metadata =
        fs::metadata(&exe_link).map_err(|_| SessionValidationError::ProcessUnavailable)?;
    Ok(ProcessExecutable {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

fn validate_agent_executable_rule(
    executable: &ProcessExecutable,
    rule: &AgentExecutableRule,
    target_uid: u32,
) -> Result<(), SessionValidationError> {
    match rule {
        AgentExecutableRule::Pi => validate_pi_agent_executable(&executable.path),
        AgentExecutableRule::Pinned { launchers } => {
            validate_pinned_agent_executable(executable, launchers, target_uid)
        }
    }
}

fn validate_pi_agent_executable(executable: &Path) -> Result<(), SessionValidationError> {
    let name = executable.file_name().and_then(|name| name.to_str());
    if matches!(name, Some("pi" | "pi-dev")) {
        Ok(())
    } else {
        Err(SessionValidationError::AgentExecutableMismatch)
    }
}

fn validate_pinned_agent_executable(
    executable: &ProcessExecutable,
    launchers: &[PathBuf],
    target_uid: u32,
) -> Result<(), SessionValidationError> {
    if launchers.is_empty() {
        return Err(SessionValidationError::AgentLaunchersMissing);
    }
    if executable.uid != target_uid {
        return Err(SessionValidationError::AgentExecutableOwnerMismatch);
    }
    if executable.mode & GROUP_OR_WORLD_WRITE_BITS != 0
        || executable.mode & EXECUTABLE_PERMISSION_BITS == 0
    {
        return Err(SessionValidationError::AgentExecutablePermissions);
    }
    for launcher in launchers {
        if pinned_launcher_matches(executable, launcher)? {
            return Ok(());
        }
    }
    Err(SessionValidationError::AgentExecutableMismatch)
}

fn pinned_launcher_matches(
    executable: &ProcessExecutable,
    launcher: &Path,
) -> Result<bool, SessionValidationError> {
    if !launcher.is_absolute() {
        return Ok(false);
    }
    let resolved =
        fs::canonicalize(launcher).map_err(|_| SessionValidationError::AgentExecutableMismatch)?;
    let metadata =
        fs::metadata(&resolved).map_err(|_| SessionValidationError::AgentExecutableMismatch)?;
    Ok(resolved == executable.path
        && metadata.dev() == executable.device
        && metadata.ino() == executable.inode)
}

fn read_process_ids(process_dir: &Path) -> Result<(u32, u32), SessionValidationError> {
    let status = fs::read_to_string(process_dir.join("status"))
        .map_err(|_| SessionValidationError::ProcessUnavailable)?;
    let uid = read_status_id(&status, "Uid:")?;
    let gid = read_status_id(&status, "Gid:")?;
    Ok((uid, gid))
}

fn read_status_id(status: &str, field: &str) -> Result<u32, SessionValidationError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|values| values.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or(SessionValidationError::ProcessUnavailable)
}

fn read_session_environment(
    process_dir: &Path,
) -> Result<HashMap<String, String>, SessionValidationError> {
    let bytes = fs::read(process_dir.join("environ"))
        .map_err(|_| SessionValidationError::ProcessUnavailable)?;
    let allowed = wayland_env();
    let env = bytes
        .split(|byte| *byte == 0)
        .filter_map(parse_environment_entry)
        .filter(|(key, _)| allowed.contains(&key.as_str()))
        .collect::<HashMap<_, _>>();

    let has_required = REQUIRED_SESSION_ENVIRONMENT
        .iter()
        .all(|key| env.get(*key).is_some_and(|value| !value.is_empty()));
    if has_required {
        Ok(env)
    } else {
        Err(SessionValidationError::MissingSessionEnvironment)
    }
}

fn parse_environment_entry(entry: &[u8]) -> Option<(String, String)> {
    let entry = std::str::from_utf8(entry).ok()?;
    let (key, value) = entry.split_once('=')?;
    Some((key.to_string(), value.to_string()))
}

fn validate_runtime_directory_owner(
    env: &HashMap<String, String>,
    uid: u32,
) -> Result<(), SessionValidationError> {
    let runtime_dir = env
        .get("XDG_RUNTIME_DIR")
        .ok_or(SessionValidationError::MissingSessionEnvironment)?;
    let metadata = fs::metadata(Path::new(runtime_dir))
        .map_err(|_| SessionValidationError::MissingSessionEnvironment)?;
    if metadata.uid() == uid {
        Ok(())
    } else {
        Err(SessionValidationError::RuntimeDirectoryOwnerMismatch)
    }
}

#[cfg(test)]
mod tests;
