use authd_protocol::{ConfirmSessionRequest, ConfirmSessionTarget, wayland_env};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

const MAX_PI_SESSION_ANCESTORS: usize = 8;
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionValidationError {
    #[error("target process is unavailable")]
    ProcessUnavailable,
    #[error("target process start time changed")]
    StartTimeMismatch,
    #[error("target process uid does not match requested uid")]
    UidMismatch,
    #[error("target process is not pi")]
    NotPiProcess,
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
    let (target, env) = match &request.target {
        ConfirmSessionTarget::Pi { pid, start_time } => {
            let target = read_and_validate_pi_target_process(
                proc_root,
                *pid,
                *start_time,
                request.target_uid,
            )?;
            let env = read_pi_session_environment(proc_root, *pid, target.uid)?;
            (target, env)
        }
        ConfirmSessionTarget::Terminal {
            leader_pid,
            leader_start_time,
            tty_device,
        } => {
            let target = read_and_validate_terminal_target_process(
                proc_root,
                *leader_pid,
                *leader_start_time,
                *tty_device,
                request.target_uid,
            )?;
            let env = read_terminal_session_environment(&target.process_dir, target.uid)?;
            (target, env)
        }
    };
    ensure_process_start_time_unchanged(&target.process_dir, target.initial_start_time)?;

    Ok(ValidatedSession {
        uid: target.uid,
        gid: target.gid,
        env,
    })
}

fn read_and_validate_pi_target_process(
    proc_root: &Path,
    pid: u32,
    start_time: u64,
    target_uid: u32,
) -> Result<ValidatedTargetProcess, SessionValidationError> {
    let process_dir = proc_root.join(pid.to_string());
    let initial_start_time = read_start_time(&process_dir)?;
    if initial_start_time != start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }

    validate_pi_executable(&process_dir)?;
    let (uid, gid) = read_process_ids(&process_dir)?;
    if uid != target_uid {
        return Err(SessionValidationError::UidMismatch);
    }

    Ok(ValidatedTargetProcess {
        process_dir,
        initial_start_time,
        uid,
        gid,
    })
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

fn read_pi_session_environment(
    proc_root: &Path,
    pi_pid: u32,
    uid: u32,
) -> Result<HashMap<String, String>, SessionValidationError> {
    let mut current_pid = pi_pid;
    for _ in 0..MAX_PI_SESSION_ANCESTORS {
        let process_dir = proc_root.join(current_pid.to_string());
        if let Some(env) = read_owned_session_environment(&process_dir, uid)? {
            return Ok(env);
        }

        let Some(parent_pid) = read_same_uid_pi_parent(proc_root, &process_dir, current_pid, uid)?
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

fn read_same_uid_pi_parent(
    proc_root: &Path,
    process_dir: &Path,
    current_pid: u32,
    uid: u32,
) -> Result<Option<u32>, SessionValidationError> {
    let parent_pid = read_process_stat(process_dir)?.parent_pid;
    if parent_pid == 0 || parent_pid == current_pid {
        return Ok(None);
    }

    let parent_dir = proc_root.join(parent_pid.to_string());
    match validate_pi_executable(&parent_dir) {
        Ok(()) => {}
        Err(SessionValidationError::NotPiProcess | SessionValidationError::ProcessUnavailable) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    let (parent_uid, _) = read_process_ids(&parent_dir)?;
    if parent_uid != uid {
        return Err(SessionValidationError::UidMismatch);
    }
    Ok(Some(parent_pid))
}

fn validate_pi_executable(process_dir: &Path) -> Result<(), SessionValidationError> {
    let executable = fs::read_link(process_dir.join("exe"))
        .map_err(|_| SessionValidationError::ProcessUnavailable)?;
    let name = executable.file_name().and_then(|name| name.to_str());
    if matches!(name, Some("pi" | "pi-dev")) {
        Ok(())
    } else {
        Err(SessionValidationError::NotPiProcess)
    }
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
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct ProcFixture {
        root: TempDir,
        pid: u32,
        uid: u32,
        runtime_dir: PathBuf,
    }

    impl ProcFixture {
        fn valid() -> Self {
            let root = tempfile::tempdir().unwrap();
            let pid = 4242;
            let uid = unsafe { libc::geteuid() };
            let process_dir = root.path().join(pid.to_string());
            fs::create_dir(&process_dir).unwrap();
            fs::write(process_dir.join("stat"), stat(pid, 987_654)).unwrap();
            fs::write(
                process_dir.join("status"),
                format!("Name:\tpi\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .unwrap();
            let executable = root.path().join("pi");
            fs::write(&executable, "").unwrap();
            symlink(&executable, process_dir.join("exe")).unwrap();
            let runtime_dir = root.path().join("runtime");
            fs::create_dir(&runtime_dir).unwrap();
            let environ = format!(
                "WAYLAND_DISPLAY=wayland-1\0XDG_RUNTIME_DIR={}\0XDG_SESSION_TYPE=wayland\0",
                runtime_dir.display()
            );
            fs::write(process_dir.join("environ"), environ.as_bytes()).unwrap();
            Self {
                root,
                pid,
                uid,
                runtime_dir,
            }
        }

        fn request(&self) -> ConfirmSessionRequest {
            ConfirmSessionRequest {
                target: authd_protocol::ConfirmSessionTarget::Pi {
                    pid: self.pid,
                    start_time: 987_654,
                },
                target_uid: self.uid,
                title: "Secrets Broker".into(),
                message: "Unlock credentials?".into(),
                detail: "mysql-gc:prod-ro".into(),
            }
        }

        fn terminal_request(&self) -> ConfirmSessionRequest {
            ConfirmSessionRequest {
                target: authd_protocol::ConfirmSessionTarget::Terminal {
                    leader_pid: self.pid,
                    leader_start_time: 987_654,
                    tty_device: 42,
                },
                target_uid: self.uid,
                title: "Secrets Broker".into(),
                message: "Unlock credentials?".into(),
                detail: "mysql-gc:prod-ro".into(),
            }
        }

        fn process_file(&self, name: &str) -> PathBuf {
            self.root.path().join(self.pid.to_string()).join(name)
        }
    }

    fn stat(pid: u32, start_time: u64) -> String {
        stat_with_session(pid, 1, 0, 0, start_time)
    }

    fn stat_with_parent(pid: u32, parent_pid: u32, start_time: u64) -> String {
        stat_with_session(pid, parent_pid, 0, 0, start_time)
    }

    fn stat_with_session(
        pid: u32,
        parent_pid: u32,
        session_id: u32,
        tty_device: i64,
        start_time: u64,
    ) -> String {
        let fields = [
            "S".to_string(),
            parent_pid.to_string(),
            "0".into(),
            session_id.to_string(),
            tty_device.to_string(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            "0".into(),
            start_time.to_string(),
            "0".into(),
            "0".into(),
        ];
        format!("{pid} (pi process) {}", fields.join(" "))
    }

    #[test]
    fn validates_matching_pi_process_and_session() {
        let fixture = ProcFixture::valid();
        let session = validate_confirm_session_at(fixture.root.path(), &fixture.request()).unwrap();

        assert_eq!(session.uid, fixture.uid);
        assert_eq!(session.gid, fixture.uid);
        assert_eq!(
            session.env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-1")
        );
        assert_eq!(
            session.env.get("XDG_RUNTIME_DIR").map(Path::new),
            Some(fixture.runtime_dir.as_path())
        );
    }

    #[test]
    fn uses_parent_pi_session_for_detached_pi_runner() {
        let fixture = ProcFixture::valid();
        let parent_pid = 4241;
        fs::write(
            fixture.process_file("stat"),
            stat_with_parent(fixture.pid, parent_pid, 987_654),
        )
        .unwrap();
        fs::write(fixture.process_file("environ"), b"").unwrap();

        let parent_dir = fixture.root.path().join(parent_pid.to_string());
        fs::create_dir(&parent_dir).unwrap();
        fs::write(parent_dir.join("stat"), stat(parent_pid, 123_456)).unwrap();
        fs::write(
            parent_dir.join("status"),
            format!(
                "Name:\tpi\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
                uid = fixture.uid
            ),
        )
        .unwrap();
        symlink(fixture.root.path().join("pi"), parent_dir.join("exe")).unwrap();
        let environ = format!(
            "WAYLAND_DISPLAY=wayland-1\0XDG_RUNTIME_DIR={}\0",
            fixture.runtime_dir.display()
        );
        fs::write(parent_dir.join("environ"), environ.as_bytes()).unwrap();

        let session = validate_confirm_session_at(fixture.root.path(), &fixture.request()).unwrap();
        assert_eq!(
            session.env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-1")
        );
    }

    #[test]
    fn validates_matching_terminal_process_and_session() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 42, 987_654),
        )
        .unwrap();

        let session =
            validate_confirm_session_at(fixture.root.path(), &fixture.terminal_request()).unwrap();

        assert_eq!(session.uid, fixture.uid);
        assert_eq!(session.gid, fixture.uid);
        assert_eq!(
            session.env.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-1")
        );
    }

    #[test]
    fn rejects_terminal_start_time_mismatch() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 42, 987_654),
        )
        .unwrap();
        let mut request = fixture.terminal_request();
        if let authd_protocol::ConfirmSessionTarget::Terminal {
            leader_start_time, ..
        } = &mut request.target
        {
            *leader_start_time += 1;
        }

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &request),
            Err(SessionValidationError::StartTimeMismatch)
        ));
    }

    #[test]
    fn rejects_terminal_target_uid_mismatch() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 42, 987_654),
        )
        .unwrap();
        let mut request = fixture.terminal_request();
        request.target_uid += 1;

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &request),
            Err(SessionValidationError::UidMismatch)
        ));
    }

    #[test]
    fn rejects_terminal_pid_that_is_not_session_leader() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, 1, 42, 987_654),
        )
        .unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.terminal_request()),
            Err(SessionValidationError::TerminalNotSessionLeader)
        ));
    }

    #[test]
    fn rejects_terminal_without_controlling_tty() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 0, 987_654),
        )
        .unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.terminal_request()),
            Err(SessionValidationError::TerminalNoControllingTty)
        ));
    }

    #[test]
    fn rejects_terminal_with_mismatched_controlling_tty() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 43, 987_654),
        )
        .unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.terminal_request()),
            Err(SessionValidationError::TerminalTtyMismatch)
        ));
    }

    #[test]
    fn rejects_terminal_missing_session_environment() {
        let fixture = ProcFixture::valid();
        fs::write(
            fixture.process_file("stat"),
            stat_with_session(fixture.pid, 1, fixture.pid, 42, 987_654),
        )
        .unwrap();
        fs::write(fixture.process_file("environ"), b"XDG_RUNTIME_DIR=/tmp\0").unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.terminal_request()),
            Err(SessionValidationError::MissingSessionEnvironment)
        ));
    }

    #[test]
    fn rejects_changed_process_start_time() {
        let fixture = ProcFixture::valid();
        let mut request = fixture.request();
        if let authd_protocol::ConfirmSessionTarget::Pi { start_time, .. } = &mut request.target {
            *start_time += 1;
        }

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &request),
            Err(SessionValidationError::StartTimeMismatch)
        ));
    }

    #[test]
    fn rejects_target_uid_mismatch() {
        let fixture = ProcFixture::valid();
        let mut request = fixture.request();
        request.target_uid += 1;

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &request),
            Err(SessionValidationError::UidMismatch)
        ));
    }

    #[test]
    fn rejects_non_pi_executable() {
        let fixture = ProcFixture::valid();
        fs::remove_file(fixture.process_file("exe")).unwrap();
        symlink("/usr/bin/curl", fixture.process_file("exe")).unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.request()),
            Err(SessionValidationError::NotPiProcess)
        ));
    }

    #[test]
    fn rejects_missing_session_environment() {
        let fixture = ProcFixture::valid();
        fs::write(fixture.process_file("environ"), b"XDG_RUNTIME_DIR=/tmp\0").unwrap();

        assert!(matches!(
            validate_confirm_session_at(fixture.root.path(), &fixture.request()),
            Err(SessionValidationError::MissingSessionEnvironment)
        ));
    }
}
