mod dialog;

use authd_policy::{PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse, SOCKET_PATH};
use dialog::{DialogResult, show_confirmation_dialog};
use peercred_ipc::{CallerInfo, Connection, Server};
use std::sync::Arc;
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

    let server = Server::bind(SOCKET_PATH)?;
    info!("authd listening on {}", SOCKET_PATH);

    loop {
        match server.accept().await {
            Ok((conn, caller)) => {
                let state = Arc::clone(&state);
                tokio::spawn(handle_connection(conn, caller, state));
            }
            Err(e) => {
                error!("accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(mut conn: Connection, caller: CallerInfo, state: Arc<AppState>) {
    info!(
        "connection from uid={} pid={} exe={:?}",
        caller.uid, caller.pid, caller.exe
    );

    let request: AuthRequest = match conn.read().await {
        Ok(r) => r,
        Err(e) => {
            error!("{}", e);
            let _ = conn
                .write(&AuthResponse::Error {
                    message: "invalid request".into(),
                })
                .await;
            return;
        }
    };

    let response = process_request(&caller, &request, &state).await;
    let _ = conn.write(&response).await;
}

async fn process_request(
    caller: &CallerInfo,
    request: &AuthRequest,
    state: &AppState,
) -> AuthResponse {
    info!("auth request: target={:?}", request.target);

    // If confirm_only from authsudo, skip policy check (authsudo already validated with real uid)
    let is_authsudo = caller.exe.ends_with("authsudo");
    if request.confirm_only && is_authsudo {
        let result = show_confirmation_dialog(caller, &request.target, &request.args, &request.env);
        return match result {
            DialogResult::Confirmed => {
                info!("user confirmed");
                AuthResponse::Success { pid: 0 }
            }
            DialogResult::Denied => AuthResponse::Denied {
                reason: "user cancelled".into(),
            },
            DialogResult::Error => AuthResponse::Error {
                message: "failed to show confirmation dialog".into(),
            },
        };
    }

    // Check policy (pass caller exe for trusted caller bypass)
    let decision = state
        .policy
        .check_with_caller(&request.target, caller.uid, Some(&caller.exe));

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
            // Show confirmation dialog (fork, drop privs, run GUI)
            let result =
                show_confirmation_dialog(caller, &request.target, &request.args, &request.env);
            match result {
                DialogResult::Confirmed => {
                    info!("user confirmed");
                }
                DialogResult::Denied => {
                    return AuthResponse::Denied {
                        reason: "user cancelled".into(),
                    };
                }
                DialogResult::Error => {
                    return AuthResponse::Error {
                        message: "failed to show confirmation dialog".into(),
                    };
                }
            }
        }
        PolicyDecision::RequireAuth => {
            // Password auth not supported via GUI - use authsudo instead
            return AuthResponse::Error {
                message: "Password auth requires terminal. Use: authsudo".into(),
            };
        }
    }

    // If confirm_only, don't spawn - just return success
    if request.confirm_only {
        return AuthResponse::Success { pid: 0 };
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
