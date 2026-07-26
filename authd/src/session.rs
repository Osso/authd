use authd_protocol::{ConfirmSessionRequest, wayland_env};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug)]
pub struct ValidatedSession {
    pub uid: u32,
    pub gid: u32,
    pub env: HashMap<String, String>,
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
    let process_dir = proc_root.join(request.pi_pid.to_string());
    let initial_start_time = read_start_time(&process_dir)?;
    if initial_start_time != request.pi_start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }

    validate_pi_executable(&process_dir)?;
    let (uid, gid) = read_process_ids(&process_dir)?;
    if uid != request.target_uid {
        return Err(SessionValidationError::UidMismatch);
    }

    let env = find_pi_session_environment(proc_root, request.pi_pid, uid)?;

    let final_start_time = read_start_time(&process_dir)?;
    if final_start_time != initial_start_time {
        return Err(SessionValidationError::StartTimeMismatch);
    }

    Ok(ValidatedSession { uid, gid, env })
}

fn read_start_time(process_dir: &Path) -> Result<u64, SessionValidationError> {
    read_process_stat(process_dir).map(|(_, start_time)| start_time)
}

fn read_process_stat(process_dir: &Path) -> Result<(u32, u64), SessionValidationError> {
    let stat = fs::read_to_string(process_dir.join("stat"))
        .map_err(|_| SessionValidationError::ProcessUnavailable)?;
    let command_end = stat
        .rfind(") ")
        .ok_or(SessionValidationError::ProcessUnavailable)?;
    let fields = stat[command_end + 2..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let parent_pid = fields
        .get(1)
        .and_then(|value| value.parse().ok())
        .ok_or(SessionValidationError::ProcessUnavailable)?;
    let start_time = fields
        .get(19)
        .and_then(|value| value.parse().ok())
        .ok_or(SessionValidationError::ProcessUnavailable)?;
    Ok((parent_pid, start_time))
}

fn find_pi_session_environment(
    proc_root: &Path,
    pi_pid: u32,
    uid: u32,
) -> Result<HashMap<String, String>, SessionValidationError> {
    let mut current_pid = pi_pid;
    for _ in 0..8 {
        let process_dir = proc_root.join(current_pid.to_string());
        match read_session_environment(&process_dir) {
            Ok(env) => {
                validate_runtime_directory_owner(&env, uid)?;
                return Ok(env);
            }
            Err(SessionValidationError::MissingSessionEnvironment) => {}
            Err(error) => return Err(error),
        }

        let (parent_pid, _) = read_process_stat(&process_dir)?;
        if parent_pid == 0 || parent_pid == current_pid {
            break;
        }
        let parent_dir = proc_root.join(parent_pid.to_string());
        match validate_pi_executable(&parent_dir) {
            Ok(()) => {}
            Err(
                SessionValidationError::NotPiProcess | SessionValidationError::ProcessUnavailable,
            ) => {
                break;
            }
            Err(error) => return Err(error),
        }
        let (parent_uid, _) = read_process_ids(&parent_dir)?;
        if parent_uid != uid {
            return Err(SessionValidationError::UidMismatch);
        }
        current_pid = parent_pid;
    }
    Err(SessionValidationError::MissingSessionEnvironment)
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

    let has_required = ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"]
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
    let metadata = fs::metadata(PathBuf::from(runtime_dir))
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
                pi_pid: self.pid,
                pi_start_time: 987_654,
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
        stat_with_parent(pid, 1, start_time)
    }

    fn stat_with_parent(pid: u32, parent_pid: u32, start_time: u64) -> String {
        format!(
            "{pid} (pi process) S {parent_pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start_time} 0 0"
        )
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
    fn rejects_changed_process_start_time() {
        let fixture = ProcFixture::valid();
        let mut request = fixture.request();
        request.pi_start_time += 1;

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
