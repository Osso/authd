use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[default]
    Password,
    None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_roundtrip() {
        let request = AuthRequest {
            target: PathBuf::from("/usr/bin/test"),
            args: vec!["--flag".into(), "value".into()],
            env: HashMap::from([("KEY".into(), "VALUE".into())]),
            password: String::new(),
        };

        let encoded = rmp_serde::to_vec(&request).unwrap();
        let decoded: AuthRequest = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.target, request.target);
        assert_eq!(decoded.args, request.args);
        assert_eq!(decoded.env, request.env);
    }

    #[test]
    fn auth_response_variants_roundtrip() {
        let responses = vec![
            AuthResponse::Success { pid: 12345 },
            AuthResponse::AuthFailed,
            AuthResponse::Denied { reason: "not allowed".into() },
            AuthResponse::UnknownTarget,
            AuthResponse::Error { message: "something went wrong".into() },
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
        assert!(matches!(rule.auth, AuthRequirement::Password));
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
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"password\"").unwrap().auth,
            AuthRequirement::Password
        ));
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"none\"").unwrap().auth,
            AuthRequirement::None
        ));
        assert!(matches!(
            toml::from_str::<PolicyRule>("target = \"/bin/x\"\nauth = \"deny\"").unwrap().auth,
            AuthRequirement::Deny
        ));
    }
}
