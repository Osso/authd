use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

pub const SOCKET_PATH: &str = "/run/authd.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Target binary to execute
    pub target: PathBuf,
    /// Arguments to pass to target
    pub args: Vec<String>,
    /// Additional environment variables
    pub env: HashMap<String, String>,
    /// User's password (empty if using cached auth)
    pub password: String,
    /// If true, only show confirmation dialog, don't spawn process
    #[serde(default)]
    pub confirm_only: bool,
    /// Optional dialog title for confirm-only callers.
    #[serde(default)]
    pub prompt_title: Option<String>,
    /// Optional dialog message/subtitle for confirm-only callers.
    #[serde(default)]
    pub prompt_message: Option<String>,
    /// Optional dialog detail text for confirm-only callers.
    #[serde(default)]
    pub prompt_detail: Option<String>,
}

/// Check if user has cached auth (no password needed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCheckRequest {
    pub target: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCheckResponse {
    /// User has valid cached auth - can proceed without password
    Cached,
    /// Password required
    PasswordRequired,
    /// Target not allowed
    Denied { reason: String },
    /// Target unknown
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResponse {
    /// Success - returns PID of spawned process
    Success { pid: u32 },
    /// Authentication failed (wrong password)
    AuthFailed,
    /// Target denied by policy
    Denied { reason: String },
    /// Target not found in any policy
    UnknownTarget,
    /// Internal daemon error
    Error { message: String },
}

/// Top-level request envelope read by authd. Keeps the legacy exec/confirm
/// flow (`Exec`) and the polkit authentication-agent flow (`Polkit`) on one
/// socket without overloading `AuthRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Legacy authsudo/authctl request: check policy, optionally confirm, spawn.
    Exec(AuthRequest),
    /// polkit agent forwarded a `BeginAuthentication`: confirm, then assert.
    Polkit(PolkitRequest),
}

/// A polkit `BeginAuthentication` forwarded from `authd-polkit-agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolkitRequest {
    /// polkit action id, e.g. `org.freedesktop.systemd1.manage-units`.
    pub action_id: String,
    /// Human-readable message supplied by polkit, shown in the dialog.
    pub message: String,
    /// Opaque cookie identifying this authentication request to polkitd.
    pub cookie: String,
    /// uid of the `unix-user` identity to assert on success.
    pub uid: u32,
    /// Wayland environment of the agent's session, for the dialog.
    pub env: HashMap<String, String>,
}

/// Result of a polkit confirm request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolkitReply {
    /// User confirmed and authd asserted the response to polkitd.
    Allowed,
    /// User declined or the request was denied by policy.
    Denied,
    /// authd failed to process the request (dialog/D-Bus error).
    Error { message: String },
}

/// Metadata about the caller, extracted from socket credentials
#[derive(Debug, Clone)]
pub struct CallerInfo {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    /// Resolved from /proc/<pid>/exe
    pub exe: PathBuf,
}

/// Policy rule (declarative, loaded from TOML)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Target binary path
    pub target: PathBuf,
    /// Groups allowed to run this target
    #[serde(default)]
    pub allow_groups: Vec<String>,
    /// Users allowed to run this target
    #[serde(default)]
    pub allow_users: Vec<String>,
    /// Caller binaries that bypass auth (e.g., "/usr/bin/claude")
    #[serde(default)]
    pub allow_callers: Vec<PathBuf>,
    /// Auth requirement: "password", "none", "deny"
    #[serde(default)]
    pub auth: AuthRequirement,
    /// Cache timeout in seconds (default 300 = 5 minutes)
    #[serde(default = "default_cache_timeout")]
    pub cache_timeout: u64,
}

fn default_cache_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthRequirement {
    /// No interaction - run immediately
    None,
    /// Show confirmation dialog (default)
    #[default]
    Confirm,
    /// Require password authentication
    Password,
    /// Always deny
    Deny,
}

/// Wayland environment variables to pass through
pub fn wayland_env() -> Vec<&'static str> {
    vec![
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
    ]
}

pub fn collect_wayland_env() -> HashMap<String, String> {
    wayland_env()
        .into_iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_request_polkit_roundtrip() {
        let request = DaemonRequest::Polkit(PolkitRequest {
            action_id: "org.freedesktop.systemd1.manage-units".into(),
            message: "Authentication is required to stop 'x.service'.".into(),
            cookie: "2-abc-1-def".into(),
            uid: 1000,
            env: HashMap::from([("WAYLAND_DISPLAY".into(), "wayland-1".into())]),
        });

        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: DaemonRequest = rmp_serde::from_slice(&encoded).unwrap();

        match decoded {
            DaemonRequest::Polkit(p) => {
                assert_eq!(p.action_id, "org.freedesktop.systemd1.manage-units");
                assert_eq!(p.cookie, "2-abc-1-def");
                assert_eq!(p.uid, 1000);
                assert_eq!(p.env.get("WAYLAND_DISPLAY").map(String::as_str), Some("wayland-1"));
            }
            other => panic!("expected Polkit, got {other:?}"),
        }
    }

    #[test]
    fn daemon_request_exec_roundtrip() {
        let request = DaemonRequest::Exec(AuthRequest {
            target: PathBuf::from("/usr/bin/test"),
            args: vec!["--flag".into()],
            env: HashMap::new(),
            password: String::new(),
            confirm_only: true,
            prompt_title: None,
            prompt_message: None,
            prompt_detail: None,
        });

        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: DaemonRequest = rmp_serde::from_slice(&encoded).unwrap();
        assert!(matches!(decoded, DaemonRequest::Exec(_)));
    }

    #[test]
    fn polkit_reply_roundtrip() {
        for reply in [
            PolkitReply::Allowed,
            PolkitReply::Denied,
            PolkitReply::Error {
                message: "boom".into(),
            },
        ] {
            let encoded = rmp_serde::to_vec(&reply).unwrap();
            let decoded: PolkitReply = rmp_serde::from_slice(&encoded).unwrap();
            assert_eq!(format!("{decoded:?}"), format!("{reply:?}"));
        }
    }

    #[test]
    fn auth_request_roundtrip() {
        let request = AuthRequest {
            target: PathBuf::from("/usr/bin/test"),
            args: vec!["--flag".into(), "value".into()],
            env: HashMap::from([("KEY".into(), "VALUE".into())]),
            password: String::new(),
            confirm_only: false,
            prompt_title: None,
            prompt_message: None,
            prompt_detail: None,
        };

        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: AuthRequest = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.target, request.target);
        assert_eq!(decoded.args, request.args);
        assert_eq!(decoded.env, request.env);
    }

    #[test]
    fn auth_request_roundtrip_with_prompt_text() {
        let request = AuthRequest {
            target: PathBuf::from("/usr/bin/test"),
            args: Vec::new(),
            env: HashMap::new(),
            password: String::new(),
            confirm_only: true,
            prompt_title: Some("Config access request".into()),
            prompt_message: Some("Allow this config access?".into()),
            prompt_detail: Some("/home/osso/.config/example".into()),
        };

        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: AuthRequest = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.prompt_title, request.prompt_title);
        assert_eq!(decoded.prompt_message, request.prompt_message);
        assert_eq!(decoded.prompt_detail, request.prompt_detail);
    }

    #[test]
    fn auth_response_variants_roundtrip() {
        let responses = vec![
            AuthResponse::Success { pid: 12345 },
            AuthResponse::AuthFailed,
            AuthResponse::Denied {
                reason: "not allowed".into(),
            },
            AuthResponse::UnknownTarget,
            AuthResponse::Error {
                message: "something went wrong".into(),
            },
        ];

        for response in responses {
            let encoded = rmp_serde::to_vec(&response).unwrap();
            let decoded: AuthResponse = rmp_serde::from_slice(&encoded).unwrap();
            assert_eq!(format!("{:?}", decoded), format!("{:?}", response));
        }
    }

    #[test]
    fn policy_rule_defaults() {
        let toml = r#"
            target = "/usr/bin/test"
        "#;
        let rule: PolicyRule = toml::from_str(toml).unwrap();

        assert_eq!(rule.target, PathBuf::from("/usr/bin/test"));
        assert!(rule.allow_groups.is_empty());
        assert!(rule.allow_users.is_empty());
        assert!(matches!(rule.auth, AuthRequirement::Confirm));
        assert_eq!(rule.cache_timeout, 300);
    }

    #[test]
    fn policy_rule_full() {
        let toml = r#"
            target = "/usr/bin/test"
            allow_groups = ["wheel", "sudo"]
            allow_users = ["admin"]
            auth = "none"
            cache_timeout = 600
        "#;
        let rule: PolicyRule = toml::from_str(toml).unwrap();

        assert_eq!(rule.target, PathBuf::from("/usr/bin/test"));
        assert_eq!(rule.allow_groups, vec!["wheel", "sudo"]);
        assert_eq!(rule.allow_users, vec!["admin"]);
        assert!(matches!(rule.auth, AuthRequirement::None));
        assert_eq!(rule.cache_timeout, 600);
    }

    #[test]
    fn auth_requirement_variants() {
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"none\"")
                .unwrap()
                .auth,
            AuthRequirement::None
        ));
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"confirm\"")
                .unwrap()
                .auth,
            AuthRequirement::Confirm
        ));
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"password\"")
                .unwrap()
                .auth,
            AuthRequirement::Password
        ));
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"deny\"")
                .unwrap()
                .auth,
            AuthRequirement::Deny
        ));
    }
}
