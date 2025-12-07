use authd_policy::{PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse, CallerInfo, SOCKET_PATH};
use std::fs;
use std::os::unix::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener as TokioUnixListener;
use tracing::{error, info};

struct AppState {
    policy: PolicyEngine,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Load policies
    let mut policy = PolicyEngine::new();
    if let Err(e) = policy.load() {
        error!("failed to load policies: {}", e);
    }

    let state = Arc::new(AppState { policy });

    // Remove stale socket
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = TokioUnixListener::bind(SOCKET_PATH)?;

    // Set socket permissions (only root and users can connect)
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o666))?;

    info!("authd listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(handle_connection(stream, state));
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }
}

fn get_caller_info(stream: &tokio::net::UnixStream) -> Result<CallerInfo, std::io::Error> {
    let cred = stream.peer_cred()?;
    let pid = cred.pid().unwrap_or(0) as u32;
    Ok(CallerInfo {
        uid: cred.uid(),
        gid: cred.gid(),
        pid,
        exe: get_exe_path(pid),
    })
}

async fn read_request(stream: &mut tokio::net::UnixStream) -> Result<AuthRequest, String> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.map_err(|e| format!("read: {}", e))?;
    rmp_serde::from_slice(&buf[..n]).map_err(|e| format!("deserialize: {}", e))
}

async fn handle_connection(mut stream: tokio::net::UnixStream, state: Arc<AppState>) {
    let caller = match get_caller_info(&stream) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to get peer credentials: {}", e);
            return;
        }
    };

    info!("connection from uid={} pid={} exe={:?}", caller.uid, caller.pid, caller.exe);

    let request = match read_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            error!("{}", e);
            let _ = send_response(&mut stream, AuthResponse::Error {
                message: "invalid request".into()
            }).await;
            return;
        }
    };

    let response = process_request(&caller, &request, &state).await;
    let _ = send_response(&mut stream, response).await;
}

async fn send_response(stream: &mut tokio::net::UnixStream, response: AuthResponse) -> std::io::Result<()> {
    let data = rmp_serde::to_vec(&response).unwrap();
    stream.write_all(&data).await
}

async fn process_request(caller: &CallerInfo, request: &AuthRequest, state: &AppState) -> AuthResponse {
    info!("auth request: target={:?}", request.target);

    // Check policy
    let decision = state.policy.check(&request.target, caller.uid);

    match decision {
        PolicyDecision::Unknown => {
            return AuthResponse::UnknownTarget;
        }
        PolicyDecision::Denied(reason) => {
            return AuthResponse::Denied { reason };
        }
        PolicyDecision::AllowImmediate => {
            // No interaction needed, proceed directly
        }
        PolicyDecision::AllowWithConfirm => {
            // User already confirmed by clicking Allow in authctl
        }
        PolicyDecision::RequireAuth => {
            // Password auth not supported via GUI - use authsudo instead
            return AuthResponse::Error {
                message: "Password auth requires terminal. Use: authsudo".into(),
            };
        }
    }

    // Spawn process via systemd-run
    match spawn_process(request).await {
        Ok(pid) => AuthResponse::Success { pid },
        Err(e) => AuthResponse::Error { message: e },
    }
}

async fn spawn_process(request: &AuthRequest) -> Result<u32, String> {
    use tokio::process::Command;

    let mut cmd = Command::new("systemd-run");
    cmd.args(["--scope", "--quiet", "--collect"]);

    // Pass environment variables (for Wayland access)
    for (key, val) in &request.env {
        cmd.args(["--setenv", &format!("{}={}", key, val)]);
    }

    cmd.arg("--");
    cmd.arg(&request.target);
    cmd.args(&request.args);

    let child = cmd.spawn().map_err(|e| format!("spawn: {}", e))?;
    let pid = child.id().unwrap_or(0);

    // Don't wait for the process to complete
    Ok(pid)
}

fn get_exe_path(pid: u32) -> PathBuf {
    fs::read_link(format!("/proc/{}/exe", pid))
        .unwrap_or_else(|_| PathBuf::from("unknown"))
}
