//! authd-polkit-agent — a polkit authentication agent backed by authd.
//!
//! Runs in the user's graphical session and registers as the session's polkit
//! authentication agent. When polkit needs the user to authenticate (e.g. for
//! `systemctl` via `org.freedesktop.systemd1.manage-units`), it forwards the
//! request to the root `authd` daemon over its Unix socket. authd shows its
//! confirm dialog and, on approval, asserts `AuthenticationAgentResponse2` to
//! polkitd. There is no password — this is an allow/forbid model, matching
//! authd's existing confirmation flow.

use std::collections::HashMap;

use anyhow::{Context, Result};
use authd_protocol::{DaemonRequest, PolkitReply, PolkitRequest, SOCKET_PATH, collect_wayland_env};
use peercred_ipc::Client;
use tracing::{error, info, warn};
use zbus::Connection;
use zbus::zvariant::{OwnedValue, Value};

const AGENT_PATH: &str = "/com/ossonet/authd/PolkitAgent";
const PK_SERVICE: &str = "org.freedesktop.PolicyKit1";
const PK_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const PK_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const LOCALE: &str = "en_US.UTF-8";

/// polkit `Identity` struct: `(sa{sv})` — kind + attribute map (e.g. uid).
type Identity = (String, HashMap<String, OwnedValue>);

/// D-Bus errors polkit understands. `Cancelled` is the canonical "user
/// dismissed the dialog" response; anything else is reported as `Failed`.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
enum AgentError {
    Failed(String),
    Cancelled(String),
}

struct Agent;

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Agent {
    async fn begin_authentication(
        &self,
        action_id: String,
        message: String,
        _icon_name: String,
        _details: HashMap<String, String>,
        cookie: String,
        identities: Vec<Identity>,
    ) -> Result<(), AgentError> {
        info!(action_id, "BeginAuthentication");

        let uid = caller_uid(&identities)
            .ok_or_else(|| AgentError::Failed("no unix-user identity offered".into()))?;

        let request = PolkitRequest {
            action_id: action_id.clone(),
            message,
            cookie,
            uid,
            env: collect_wayland_env(),
        };

        match ask_authd(request).await {
            Ok(PolkitReply::Allowed) => {
                info!(action_id, "granted");
                Ok(())
            }
            Ok(PolkitReply::Denied) => {
                info!(action_id, "denied by user");
                Err(AgentError::Cancelled("user declined".into()))
            }
            Ok(PolkitReply::Error { message }) => {
                error!(action_id, %message, "authd error");
                Err(AgentError::Failed(message))
            }
            Err(e) => {
                error!(action_id, error = %e, "could not reach authd");
                Err(AgentError::Failed(format!("authd unreachable: {e}")))
            }
        }
    }

    async fn cancel_authentication(&self, cookie: String) {
        // authd's dialog has its own timeout; nothing to actively cancel yet.
        warn!(cookie, "CancelAuthentication (no-op)");
    }
}

/// Extract the uid of the `unix-user` identity polkit offered for this action.
fn caller_uid(identities: &[Identity]) -> Option<u32> {
    identities
        .iter()
        .find(|(kind, _)| kind == "unix-user")
        .and_then(|(_, attrs)| attrs.get("uid"))
        .and_then(|v| u32::try_from(v.clone()).ok())
}

/// Forward the request to authd over its Unix socket (blocking IPC moved off
/// the async executor so the dialog wait doesn't stall other work).
async fn ask_authd(request: PolkitRequest) -> Result<PolkitReply> {
    let socket = std::env::var("AUTHD_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string());
    tokio::task::spawn_blocking(move || {
        Client::call::<_, _, PolkitReply>(&socket, &DaemonRequest::Polkit(request))
            .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await
    .context("join blocking IPC task")?
}

fn session_id() -> Result<String> {
    std::env::var("XDG_SESSION_ID")
        .context("XDG_SESSION_ID not set (agent must run in the graphical session)")
}

async fn register_agent(conn: &Connection, session: &str) -> Result<()> {
    let mut attrs: HashMap<&str, Value> = HashMap::new();
    attrs.insert("session-id", Value::from(session));
    let subject = ("unix-session", attrs);

    conn.call_method(
        Some(PK_SERVICE),
        PK_AUTHORITY_PATH,
        Some(PK_AUTHORITY_IFACE),
        "RegisterAuthenticationAgent",
        &(subject, LOCALE, AGENT_PATH),
    )
    .await
    .context("RegisterAuthenticationAgent (another agent already registered?)")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let session = session_id()?;
    let conn = Connection::system()
        .await
        .context("connect to system bus")?;

    conn.object_server()
        .at(AGENT_PATH, Agent)
        .await
        .context("serve AuthenticationAgent object")?;

    register_agent(&conn, &session).await?;
    info!(session, agent_path = AGENT_PATH, "registered polkit agent");

    // Run until killed; polkit auto-unregisters when our bus name drops.
    std::future::pending::<()>().await;
    Ok(())
}
