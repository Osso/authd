use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
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
            format!(
                "Name:\tpi\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            ),
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
        let metadata = fs::metadata(self.process_file("exe")).unwrap();
        ConfirmSessionRequest {
            target: authd_protocol::ConfirmSessionTarget::Agent {
                name: "Pi".into(),
                executable_rule: authd_protocol::AgentExecutableRule::Pi,
                pid: self.pid,
                start_time: 987_654,
                executable_device: metadata.dev(),
                executable_inode: metadata.ino(),
                terminal: None,
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
fn validates_configured_agent_process_and_terminal_origin() {
    let fixture = ProcFixture::valid();
    let leader_pid = 4000;
    let tty_device = 42;
    fs::set_permissions(
        fixture.root.path().join("pi"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        fixture.process_file("stat"),
        stat_with_session(fixture.pid, leader_pid, leader_pid, tty_device, 987_654),
    )
    .unwrap();
    let leader_dir = fixture.root.path().join(leader_pid.to_string());
    fs::create_dir(&leader_dir).unwrap();
    fs::write(
        leader_dir.join("stat"),
        stat_with_session(leader_pid, 1, leader_pid, tty_device, 123_456),
    )
    .unwrap();
    fs::write(
        leader_dir.join("status"),
        format!(
            "Name:\tzsh\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
            uid = fixture.uid
        ),
    )
    .unwrap();
    let terminal_executable = fixture.root.path().join("zsh");
    fs::write(&terminal_executable, "").unwrap();
    symlink(&terminal_executable, leader_dir.join("exe")).unwrap();
    let launcher = fixture.root.path().join("claude");
    symlink(fixture.root.path().join("pi"), &launcher).unwrap();
    let metadata = fs::metadata(fixture.process_file("exe")).unwrap();
    let request = ConfirmSessionRequest {
        target: authd_protocol::ConfirmSessionTarget::Agent {
            name: "Claude Code".into(),
            executable_rule: authd_protocol::AgentExecutableRule::Pinned {
                launchers: vec![launcher],
            },
            pid: fixture.pid,
            start_time: 987_654,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
            terminal: Some(authd_protocol::AgentTerminalSession {
                leader_pid,
                leader_start_time: 123_456,
                tty_device,
            }),
        },
        target_uid: fixture.uid,
        title: "Secrets Broker".into(),
        message: "Unlock credentials?".into(),
        detail: "mysql-gc:prod".into(),
    };

    let session = validate_confirm_session_at(fixture.root.path(), &request).unwrap();

    assert_eq!(session.uid, fixture.uid);
    assert_eq!(session.gid, fixture.uid);
    assert_eq!(
        session.env.get("WAYLAND_DISPLAY").map(String::as_str),
        Some("wayland-1")
    );
}

#[test]
fn rejects_configured_agent_without_terminal_origin() {
    let fixture = ProcFixture::valid();
    fs::set_permissions(
        fixture.root.path().join("pi"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let launcher = fixture.root.path().join("claude");
    symlink(fixture.root.path().join("pi"), &launcher).unwrap();
    let metadata = fs::metadata(fixture.process_file("exe")).unwrap();
    let request = ConfirmSessionRequest {
        target: authd_protocol::ConfirmSessionTarget::Agent {
            name: "Claude Code".into(),
            executable_rule: authd_protocol::AgentExecutableRule::Pinned {
                launchers: vec![launcher],
            },
            pid: fixture.pid,
            start_time: 987_654,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
            terminal: None,
        },
        target_uid: fixture.uid,
        title: "Secrets Broker".into(),
        message: "Unlock credentials?".into(),
        detail: "mysql-gc:prod".into(),
    };

    assert!(matches!(
        validate_confirm_session_at(fixture.root.path(), &request),
        Err(SessionValidationError::AgentTerminalRequired)
    ));
}

#[test]
fn rejects_non_matching_pinned_executable_before_owner_policy() {
    let fixture = tempfile::tempdir().unwrap();
    let trusted = fixture.path().join("claude");
    fs::write(&trusted, "").unwrap();
    let executable = ProcessExecutable {
        path: "/usr/bin/zsh".into(),
        device: 1,
        inode: 2,
        uid: 0,
        mode: 0o755,
    };
    let launchers = [trusted];

    let result = validate_pinned_agent_executable(&executable, &launchers, 1000);

    assert_eq!(result, Err(SessionValidationError::AgentExecutableMismatch));
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
    if let authd_protocol::ConfirmSessionTarget::Agent { start_time, .. } = &mut request.target {
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
fn rejects_non_matching_pi_agent_executable() {
    let fixture = ProcFixture::valid();
    fs::remove_file(fixture.process_file("exe")).unwrap();
    symlink("/usr/bin/curl", fixture.process_file("exe")).unwrap();

    assert!(matches!(
        validate_confirm_session_at(fixture.root.path(), &fixture.request()),
        Err(SessionValidationError::AgentExecutableMismatch)
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
