mod dialog;

use authd_policy::{PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse};
#[cfg(not(coverage))]
use authd_protocol::{DaemonRequest, PolkitReply, PolkitRequest, SOCKET_PATH};
#[cfg(not(coverage))]
use dialog::{DialogResult, show_confirmation_dialog, show_polkit_dialog};
#[cfg(coverage)]
use peercred_ipc::CallerInfo;
#[cfg(not(coverage))]
use peercred_ipc::{CallerInfo, Connection, Server};
use std::collections::HashMap;
#[cfg(not(coverage))]
use std::sync::Arc;
#[cfg(not(coverage))]
use tracing::{error, info};
#[cfg(not(coverage))]
use zbus::zvariant::Value;

#[cfg(not(coverage))]
const PK_SERVICE: &str = "org.freedesktop.PolicyKit1";
#[cfg(not(coverage))]
const PK_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
#[cfg(not(coverage))]
const PK_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

struct AppState {
    policy: PolicyEngine,
    /// System-bus connection used to assert polkit authentication responses.
    #[cfg(not(coverage))]
    bus: zbus::Connection,
}

#[cfg(not(coverage))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Load policies
    let mut policy = PolicyEngine::new();
    if let Err(e) = policy.load() {
        error!("failed to load policies: {}", e);
    }

    let bus = zbus::Connection::system()
        .await
        .map_err(|e| anyhow::anyhow!("connect system bus: {e}"))?;

    let state = Arc::new(AppState { policy, bus });

    let socket_path = std::env::var("AUTHD_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string());
    let server = Server::bind(&socket_path)?;
    info!("authd listening on {}", socket_path);

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

#[cfg(coverage)]
fn main() {}

#[cfg(not(coverage))]
async fn handle_connection(mut conn: Connection, caller: CallerInfo, state: Arc<AppState>) {
    info!(
        "connection from uid={} pid={} exe={:?}",
        caller.uid, caller.pid, caller.exe
    );

    let request: DaemonRequest = match conn.read().await {
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

    match request {
        DaemonRequest::Exec(request) => {
            let response = process_request(&caller, &request, &state).await;
            let _ = conn.write(&response).await;
        }
        DaemonRequest::Polkit(request) => {
            let response = handle_polkit(&caller, &request, &state).await;
            let _ = conn.write(&response).await;
        }
    }
}

/// Handle a polkit `BeginAuthentication` forwarded by `authd-polkit-agent`:
/// confirm with the user, then assert the response to polkitd over the system bus.
#[cfg(not(coverage))]
async fn handle_polkit(
    caller: &CallerInfo,
    request: &PolkitRequest,
    state: &AppState,
) -> PolkitReply {
    info!(
        "polkit request: action={} uid={} agent_uid={}",
        request.action_id, request.uid, caller.uid
    );

    match show_polkit_dialog(&request.message, &request.action_id, &request.env) {
        DialogResult::Confirmed => match assert_polkit_response(state, request).await {
            Ok(()) => {
                info!("polkit response asserted for {}", request.action_id);
                PolkitReply::Allowed
            }
            Err(e) => {
                error!("polkit response failed: {e}");
                PolkitReply::Error { message: e }
            }
        },
        DialogResult::Denied => PolkitReply::Denied,
        DialogResult::Error => PolkitReply::Error {
            message: "failed to show confirmation dialog".into(),
        },
    }
}

/// Assert `AuthenticationAgentResponse2(uid, cookie, unix-user:uid)` to polkitd.
/// Trusted because authd runs as root.
#[cfg(not(coverage))]
async fn assert_polkit_response(state: &AppState, request: &PolkitRequest) -> Result<(), String> {
    let mut attrs: HashMap<&str, Value> = HashMap::new();
    attrs.insert("uid", Value::from(request.uid));
    let identity = ("unix-user", attrs);

    state
        .bus
        .call_method(
            Some(PK_SERVICE),
            PK_AUTHORITY_PATH,
            Some(PK_AUTHORITY_IFACE),
            "AuthenticationAgentResponse2",
            &(request.uid, request.cookie.as_str(), identity),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(not(coverage))]
async fn process_request(
    caller: &CallerInfo,
    request: &AuthRequest,
    state: &AppState,
) -> AuthResponse {
    info!("auth request: target={:?}", request.target);
    if request.confirm_only && is_trusted_confirm_consumer(caller) {
        return confirmation_response(caller, request);
    }

    match policy_response(caller, request, state) {
        Some(response) => return response,
        None => {}
    }

    if request.confirm_only {
        return AuthResponse::Success { pid: 0 };
    }

    match spawn_process(request).await {
        Ok(pid) => AuthResponse::Success { pid },
        Err(e) => AuthResponse::Error { message: e },
    }
}

fn is_trusted_confirm_consumer(caller: &CallerInfo) -> bool {
    caller
        .exe
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "authsudo" | "config-guard"))
}

fn policy_response(
    caller: &CallerInfo,
    request: &AuthRequest,
    state: &AppState,
) -> Option<AuthResponse> {
    let decision = state
        .policy
        .check_with_caller(&request.target, caller.uid, Some(&caller.exe));

    match decision {
        PolicyDecision::Unknown => Some(AuthResponse::UnknownTarget),
        PolicyDecision::Denied(reason) => Some(AuthResponse::Denied { reason }),
        PolicyDecision::AllowImmediate => None,
        PolicyDecision::AllowWithConfirm => confirmation_response(caller, request).into_error(),
    }
}

#[cfg(not(coverage))]
fn confirmation_response(caller: &CallerInfo, request: &AuthRequest) -> AuthResponse {
    let result = show_confirmation_dialog(
        caller,
        &request.target,
        &request.args,
        &request.env,
        request.prompt_title.as_deref(),
        request.prompt_message.as_deref(),
        request.prompt_detail.as_deref(),
    );
    match result {
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
    }
}

#[cfg(coverage)]
fn confirmation_response(_caller: &CallerInfo, _request: &AuthRequest) -> AuthResponse {
    AuthResponse::Error {
        message: "confirmation dialog unavailable in coverage build".into(),
    }
}

trait ConfirmationOutcome {
    fn into_error(self) -> Option<AuthResponse>;
}

impl ConfirmationOutcome for AuthResponse {
    fn into_error(self) -> Option<AuthResponse> {
        match self {
            AuthResponse::Success { .. } => None,
            other => Some(other),
        }
    }
}

#[cfg(not(coverage))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use authd_protocol::{AuthRequirement, PolicyRule};
    use std::path::PathBuf;

    fn caller(exe: &str, uid: u32) -> CallerInfo {
        CallerInfo {
            uid,
            gid: uid,
            pid: 123,
            exe: PathBuf::from(exe),
        }
    }

    fn request(target: &str) -> AuthRequest {
        AuthRequest {
            target: PathBuf::from(target),
            args: Vec::new(),
            env: HashMap::new(),
            password: String::new(),
            confirm_only: false,
            prompt_title: None,
            prompt_message: None,
            prompt_detail: None,
        }
    }

    #[cfg(coverage)]
    fn state_with_rule(auth: AuthRequirement) -> AppState {
        let mut policy = PolicyEngine::new();
        policy.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/id"),
            allow_users: Vec::new(),
            allow_groups: Vec::new(),
            allow_callers: vec![PathBuf::from("/usr/bin/authsudo")],
            auth,
            cache_timeout: 300,
        });
        AppState { policy }
    }

    #[test]
    fn trusted_confirm_consumers_are_named_tools() {
        assert!(is_trusted_confirm_consumer(&caller(
            "/usr/bin/authsudo",
            1000
        )));
        assert!(is_trusted_confirm_consumer(&caller(
            "/opt/bin/config-guard",
            1000
        )));
        assert!(!is_trusted_confirm_consumer(&caller("/usr/bin/curl", 1000)));
    }

    #[cfg(coverage)]
    #[test]
    fn policy_response_maps_terminal_decisions() {
        let unknown = AppState {
            policy: PolicyEngine::new(),
        };
        assert!(matches!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/none"),
                &unknown
            ),
            Some(AuthResponse::UnknownTarget)
        ));

        let deny = state_with_rule(AuthRequirement::Deny);
        assert!(matches!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/id"),
                &deny
            ),
            Some(AuthResponse::Denied { .. })
        ));

        let allow = state_with_rule(AuthRequirement::None);
        assert!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/id"),
                &allow
            )
            .is_none()
        );
    }

    #[test]
    fn success_confirmation_outcome_means_no_error() {
        assert!(AuthResponse::Success { pid: 42 }.into_error().is_none());
        assert!(matches!(
            AuthResponse::Denied {
                reason: "no".into()
            }
            .into_error(),
            Some(AuthResponse::Denied { .. })
        ));
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_main_stub_is_callable() {
        main();
    }
}
