use authd_protocol::{AuthRequirement, PolicyRule};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{info, warn};

const POLICY_DIR: &str = "/etc/authd/policies.d";

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error in {file}: {error}")]
    Parse { file: PathBuf, error: String },
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: HashMap<PathBuf, PolicyRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule directly (useful for testing)
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.insert(rule.target.clone(), rule);
    }

    /// Load policies from TOML string
    pub fn load_from_str(&mut self, content: &str) -> Result<usize, PolicyError> {
        let config: PolicyFile = toml::from_str(content).map_err(|e| PolicyError::Parse {
            file: PathBuf::from("<string>"),
            error: e.to_string(),
        })?;

        let count = config.rules.len();
        for rule in config.rules {
            self.rules.insert(rule.target.clone(), rule);
        }
        Ok(count)
    }

    /// Load all policies from the policy directory
    pub fn load(&mut self) -> Result<(), PolicyError> {
        let policy_dir = Path::new(POLICY_DIR);
        if !policy_dir.exists() {
            warn!("policy directory {} does not exist", POLICY_DIR);
            return Ok(());
        }

        for entry in fs::read_dir(policy_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "toml") {
                match self.load_file(&path) {
                    Ok(count) => info!("loaded {} rules from {:?}", count, path),
                    Err(e) => warn!("failed to load {:?}: {}", path, e),
                }
            }
        }

        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<usize, PolicyError> {
        let content = fs::read_to_string(path)?;
        let config: PolicyFile =
            toml::from_str(&content).map_err(|e| PolicyError::Parse {
                file: path.to_path_buf(),
                error: e.to_string(),
            })?;

        let count = config.rules.len();
        for rule in config.rules {
            self.rules.insert(rule.target.clone(), rule);
        }

        Ok(count)
    }

    /// Check if a user is authorized to run a target
    pub fn check(&self, target: &Path, uid: u32) -> PolicyDecision {
        let Some(rule) = self.rules.get(target) else {
            return PolicyDecision::Unknown;
        };

        // Check user/group permissions
        let username = crate::pam::username_from_uid(uid);
        let user_allowed = username
            .as_ref()
            .is_some_and(|u| rule.allow_users.contains(u));

        let group_allowed = rule
            .allow_groups
            .iter()
            .any(|g| crate::pam::user_in_group(uid, g));

        if !user_allowed && !group_allowed {
            return PolicyDecision::Denied("user not authorized".into());
        }

        match rule.auth {
            AuthRequirement::None => PolicyDecision::Allow,
            AuthRequirement::Password => PolicyDecision::RequireAuth,
            AuthRequirement::Deny => PolicyDecision::Denied("target denied by policy".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    RequireAuth,
    Denied(String),
    Unknown,
}

#[derive(Debug, serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_target() {
        let engine = PolicyEngine::new();
        let decision = engine.check(Path::new("/usr/bin/unknown"), 1000);
        assert!(matches!(decision, PolicyDecision::Unknown));
    }

    #[test]
    fn load_from_string() {
        let mut engine = PolicyEngine::new();
        let toml = r#"
            [[rules]]
            target = "/usr/bin/test1"
            allow_users = ["testuser"]
            auth = "none"

            [[rules]]
            target = "/usr/bin/test2"
            allow_groups = ["wheel"]
            auth = "password"
        "#;

        let count = engine.load_from_str(toml).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn deny_policy() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/forbidden"),
            allow_users: vec!["root".into()],
            allow_groups: vec![],
            auth: AuthRequirement::Deny,
            cache_timeout: 300,
        });

        // Even allowed user gets denied due to auth=deny
        let decision = engine.check(Path::new("/usr/bin/forbidden"), 0);
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn current_user_in_wheel() {
        // Test with current user - assumes they're in wheel group
        let uid = users::get_current_uid();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/wheeltest"),
            allow_users: vec![],
            allow_groups: vec!["wheel".into()],
            auth: AuthRequirement::None,
            cache_timeout: 300,
        });

        let decision = engine.check(Path::new("/usr/bin/wheeltest"), uid);
        // This test passes if user is in wheel, fails with Denied otherwise
        // Skip assertion if user not in wheel (CI environments)
        if crate::pam::user_in_group(uid, "wheel") {
            assert!(matches!(decision, PolicyDecision::Allow));
        }
    }

    #[test]
    fn current_user_by_name() {
        let uid = users::get_current_uid();
        let username = crate::pam::username_from_uid(uid).unwrap();

        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/usertest"),
            allow_users: vec![username],
            allow_groups: vec![],
            auth: AuthRequirement::Password,
            cache_timeout: 300,
        });

        let decision = engine.check(Path::new("/usr/bin/usertest"), uid);
        assert!(matches!(decision, PolicyDecision::RequireAuth));
    }

    #[test]
    fn user_not_authorized() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/restricted"),
            allow_users: vec!["nonexistent_user_xyz".into()],
            allow_groups: vec!["nonexistent_group_xyz".into()],
            auth: AuthRequirement::None,
            cache_timeout: 300,
        });

        let decision = engine.check(Path::new("/usr/bin/restricted"), 1000);
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }
}
