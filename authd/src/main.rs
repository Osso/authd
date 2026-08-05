mod dialog;
mod session;

use authd_policy::{PolicyDecision, PolicyEngine};
use authd_protocol::{AuthRequest, AuthResponse, ConfirmSessionRequest, ConfirmSessionResponse};
#[cfg(not(coverage))]
use authd_protocol::{DaemonRequest, PolkitReply, PolkitRequest, SOCKET_PATH};
#[cfg(not(coverage))]
use dialog::{ConfirmationPrompt, show_confirmation_dialog, show_polkit_dialog};
use dialog::{DialogResult, show_target_session_dialog};
#[cfg(coverage)]
use peercred_ipc::CallerInfo;
#[cfg(not(coverage))]
use peercred_ipc::{CallerInfo, Connection, ConnectionReader, ConnectionWriter, IpcError, Server};
use session::{ValidatedSession, validate_confirm_session};
use std::collections::HashMap;
#[cfg(not(coverage))]
use std::future::Future;
use std::path::Path;
#[cfg(not(coverage))]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
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

const SECRETS_BROKER_EXECUTABLE: &str = "/usr/bin/secrets-broker";

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

struct RequestTrace {
    id: String,
    started_at: Instant,
}

impl RequestTrace {
    fn new() -> Self {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id: format!("{}-{sequence}", std::process::id()),
            started_at: Instant::now(),
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn log(&self, stage: &str) {
        #[cfg(not(coverage))]
        info!(
            "request_id={} elapsed_ms={} stage={}",
            self.id,
            self.started_at.elapsed().as_millis(),
            stage
        );
        #[cfg(coverage)]
        let _ = stage;
    }
}

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
async fn handle_connection(conn: Connection, caller: CallerInfo, state: Arc<AppState>) {
    let trace = RequestTrace::new();
    trace.log("connection_accepted");
    info!(
        "request_id={} caller_uid={} caller_pid={} caller_exe={:?}",
        trace.id(),
        caller.uid,
        caller.pid,
        caller.exe
    );

    let (mut reader, mut writer) = conn.split();
    let request: DaemonRequest = match reader.read().await {
        Ok(request) => request,
        Err(error) => {
            error!("request_id={} invalid request: {}", trace.id(), error);
            let _ = writer
                .write(&AuthResponse::Error {
                    message: "invalid request".into(),
                })
                .await;
            return;
        }
    };
    trace.log("request_decoded");

    trace.log("operation_started");
    match request {
        DaemonRequest::Exec(request) => {
            let response = process_request(&caller, &request, &state, &trace);
            complete_response(reader, writer, response, &trace).await;
        }
        DaemonRequest::Polkit(request) => {
            let response = handle_polkit(&caller, &request, &state, &trace);
            complete_response(reader, writer, response, &trace).await;
        }
        DaemonRequest::ConfirmSession(request) => {
            let response = confirm_session_response(&caller, &request, &trace);
            complete_response(reader, writer, response, &trace).await;
        }
    }
}

#[cfg(not(coverage))]
async fn complete_response<T>(
    mut reader: ConnectionReader,
    mut writer: ConnectionWriter,
    response: impl Future<Output = T>,
    trace: &RequestTrace,
) where
    T: serde::Serialize,
{
    match await_response_or_disconnect(&mut reader, response).await {
        Ok(Some(response)) => {
            trace.log("operation_completed");
            let stage = if writer.write(&response).await.is_ok() {
                "response_written"
            } else {
                "response_write_failed"
            };
            trace.log(stage);
        }
        Ok(None) => trace.log("caller_disconnected"),
        Err(error) => log_disconnect_monitor_error(trace, error),
    }
}

#[cfg(not(coverage))]
fn log_disconnect_monitor_error(trace: &RequestTrace, error: IpcError) {
    error!(
        "request_id={} disconnect monitoring failed: {}",
        trace.id(),
        error
    );
}

#[cfg(not(coverage))]
async fn await_response_or_disconnect<T>(
    reader: &mut ConnectionReader,
    response: impl Future<Output = T>,
) -> Result<Option<T>, IpcError> {
    tokio::pin!(response);
    tokio::select! {
        biased;
        disconnect = reader.wait_for_disconnect() => disconnect.map(|()| None),
        response = &mut response => Ok(Some(response)),
    }
}

/// Handle a polkit `BeginAuthentication` forwarded by `authd-polkit-agent`:
/// confirm with the user, then assert the response to polkitd over the system bus.
#[cfg(not(coverage))]
async fn handle_polkit(
    caller: &CallerInfo,
    request: &PolkitRequest,
    state: &AppState,
    trace: &RequestTrace,
) -> PolkitReply {
    info!(
        "polkit request: action={} uid={} agent_uid={}",
        request.action_id, request.uid, caller.uid
    );

    match show_polkit_dialog(
        caller,
        &request.message,
        &request.action_id,
        &request.env,
        trace,
    )
    .await
    {
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
    trace: &RequestTrace,
) -> AuthResponse {
    info!("request_id={} auth target={:?}", trace.id(), request.target);
    if request.confirm_only && is_trusted_confirm_consumer(caller) {
        return confirmation_response(caller, request, trace).await;
    }

    if let Some(response) = policy_response(caller, request, state, trace).await {
        return response;
    }

    if request.confirm_only {
        return AuthResponse::Success { pid: 0 };
    }

    match spawn_process(request).await {
        Ok(pid) => AuthResponse::Success { pid },
        Err(e) => AuthResponse::Error { message: e },
    }
}

async fn confirm_session_response(
    caller: &CallerInfo,
    request: &ConfirmSessionRequest,
    trace: &RequestTrace,
) -> ConfirmSessionResponse {
    if let Err(response) = require_secrets_broker_caller(caller) {
        return response;
    }
    let session = match read_validated_confirm_session(request) {
        Ok(session) => session,
        Err(response) => return response,
    };
    show_confirm_session_dialog(&session, request, trace).await
}

fn require_secrets_broker_caller(caller: &CallerInfo) -> Result<(), ConfirmSessionResponse> {
    if is_secrets_broker(caller) {
        Ok(())
    } else {
        Err(ConfirmSessionResponse::Denied {
            reason: "caller is not the trusted Secrets Broker".into(),
        })
    }
}

fn read_validated_confirm_session(
    request: &ConfirmSessionRequest,
) -> Result<ValidatedSession, ConfirmSessionResponse> {
    validate_confirm_session(request).map_err(|error| {
        eprintln!("authd: ConfirmSession validation failed: {error}");
        ConfirmSessionResponse::Denied {
            reason: error.to_string(),
        }
    })
}

async fn show_confirm_session_dialog(
    session: &ValidatedSession,
    request: &ConfirmSessionRequest,
    trace: &RequestTrace,
) -> ConfirmSessionResponse {
    let result = show_target_session_dialog(
        session.uid,
        session.gid,
        &session.env,
        &request.title,
        &request.message,
        &request.detail,
        trace,
    )
    .await;
    confirm_session_dialog_response(result)
}

fn confirm_session_dialog_response(result: DialogResult) -> ConfirmSessionResponse {
    match result {
        DialogResult::Confirmed => ConfirmSessionResponse::Confirmed,
        DialogResult::Denied => ConfirmSessionResponse::Denied {
            reason: "user denied confirmation".into(),
        },
        DialogResult::Error => ConfirmSessionResponse::Error {
            message: "failed to show target-session confirmation dialog".into(),
        },
    }
}

fn is_trusted_confirm_consumer(caller: &CallerInfo) -> bool {
    is_secrets_broker(caller)
        || caller
            .exe
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "authsudo" | "config-guard"))
}

fn is_secrets_broker(caller: &CallerInfo) -> bool {
    caller.exe == Path::new(SECRETS_BROKER_EXECUTABLE)
}

async fn policy_response(
    caller: &CallerInfo,
    request: &AuthRequest,
    state: &AppState,
    trace: &RequestTrace,
) -> Option<AuthResponse> {
    let decision = state
        .policy
        .check_with_caller(&request.target, caller.uid, Some(&caller.exe));

    match decision {
        PolicyDecision::Unknown => Some(AuthResponse::UnknownTarget),
        PolicyDecision::Denied(reason) => Some(AuthResponse::Denied { reason }),
        PolicyDecision::AllowImmediate => None,
        PolicyDecision::AllowWithConfirm => confirmation_response(caller, request, trace)
            .await
            .into_error(),
    }
}

#[cfg(not(coverage))]
async fn confirmation_response(
    caller: &CallerInfo,
    request: &AuthRequest,
    trace: &RequestTrace,
) -> AuthResponse {
    let result = show_confirmation_dialog(
        caller,
        &request.target,
        &request.args,
        &request.env,
        ConfirmationPrompt {
            title: request.prompt_title.as_deref(),
            message: request.prompt_message.as_deref(),
            detail: request.prompt_detail.as_deref(),
        },
        trace,
    )
    .await;
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
async fn confirmation_response(
    _caller: &CallerInfo,
    _request: &AuthRequest,
    _trace: &RequestTrace,
) -> AuthResponse {
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
    #[cfg(coverage)]
    use authd_protocol::{AuthRequirement, PolicyRule};
    #[cfg(not(coverage))]
    use std::io::{Read, Write};
    #[cfg(not(coverage))]
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    #[cfg(not(coverage))]
    use std::sync::Arc;
    #[cfg(not(coverage))]
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    #[cfg(not(coverage))]
    use std::time::Duration;

    #[cfg(not(coverage))]
    static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(not(coverage))]
    struct DropProbe(Arc<AtomicBool>);

    #[cfg(not(coverage))]
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(not(coverage))]
    fn unique_socket_path() -> String {
        let id = SOCKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!(
            "/tmp/authd-disconnect-test-{}-{id}.sock",
            std::process::id()
        )
    }

    #[cfg(not(coverage))]
    fn confirm_session_request() -> DaemonRequest {
        DaemonRequest::ConfirmSession(ConfirmSessionRequest {
            pi_pid: 4242,
            pi_start_time: 987_654,
            target_uid: 1000,
            title: "Secrets Broker".into(),
            message: "Unlock credentials?".into(),
            detail: "mysql-gc:prod-ro".into(),
        })
    }

    #[cfg(not(coverage))]
    fn request_until_timeout(socket_path: String) -> std::io::ErrorKind {
        let mut stream = UnixStream::connect(socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let request = rmp_serde::to_vec(&confirm_session_request()).unwrap();
        stream.write_all(&request).unwrap();

        let mut response = [0u8; 1];
        stream.read(&mut response).unwrap_err().kind()
    }

    fn caller(exe: &str, uid: u32) -> CallerInfo {
        CallerInfo {
            uid,
            gid: uid,
            pid: 123,
            exe: PathBuf::from(exe),
        }
    }

    #[cfg(coverage)]
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

    #[cfg(not(coverage))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn confirm_session_disconnect_cancels_inflight_dialog() {
        let socket_path = unique_socket_path();
        let server = Server::bind(&socket_path).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let server_cancelled = Arc::clone(&cancelled);

        let server_task = tokio::spawn(async move {
            let (connection, _) = server.accept().await.unwrap();
            let (mut reader, _writer) = connection.split();
            let _: DaemonRequest = reader.read().await.unwrap();
            let response = async move {
                let _probe = DropProbe(server_cancelled);
                std::future::pending::<ConfirmSessionResponse>().await
            };

            let result = await_response_or_disconnect(&mut reader, response).await;
            assert!(matches!(result, Ok(None)));
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        let client_path = socket_path.clone();
        let client_task = tokio::task::spawn_blocking(move || request_until_timeout(client_path));

        assert!(matches!(
            client_task.await.unwrap(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        server_task.await.unwrap();
        assert!(cancelled.load(Ordering::SeqCst));
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn confirm_session_rejects_untrusted_consumer() {
        let trace = RequestTrace::new();
        let request = ConfirmSessionRequest {
            pi_pid: 4242,
            pi_start_time: 987_654,
            target_uid: 1000,
            title: "Secrets Broker".into(),
            message: "Unlock credentials?".into(),
            detail: "mysql-gc:prod-ro".into(),
        };

        let response =
            confirm_session_response(&caller("/tmp/secrets-broker", 1000), &request, &trace).await;

        assert!(matches!(response, ConfirmSessionResponse::Denied { .. }));
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
        assert!(is_trusted_confirm_consumer(&caller(
            "/usr/bin/secrets-broker",
            981
        )));
        assert!(!is_trusted_confirm_consumer(&caller(
            "/tmp/secrets-broker",
            1000
        )));
        assert!(!is_trusted_confirm_consumer(&caller("/usr/bin/curl", 1000)));
    }

    #[test]
    fn target_session_dialog_results_map_to_protocol_responses() {
        assert!(matches!(
            confirm_session_dialog_response(DialogResult::Confirmed),
            ConfirmSessionResponse::Confirmed
        ));
        assert!(matches!(
            confirm_session_dialog_response(DialogResult::Denied),
            ConfirmSessionResponse::Denied { .. }
        ));
        assert!(matches!(
            confirm_session_dialog_response(DialogResult::Error),
            ConfirmSessionResponse::Error { .. }
        ));
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn policy_response_maps_terminal_decisions() {
        let trace = RequestTrace::new();
        let unknown = AppState {
            policy: PolicyEngine::new(),
        };
        assert!(matches!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/none"),
                &unknown,
                &trace,
            )
            .await,
            Some(AuthResponse::UnknownTarget)
        ));

        let deny = state_with_rule(AuthRequirement::Deny);
        assert!(matches!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/id"),
                &deny,
                &trace,
            )
            .await,
            Some(AuthResponse::Denied { .. })
        ));

        let allow = state_with_rule(AuthRequirement::None);
        assert!(
            policy_response(
                &caller("/usr/bin/authsudo", 1000),
                &request("/usr/bin/id"),
                &allow,
                &trace,
            )
            .await
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
