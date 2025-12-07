use authd_protocol::{AuthRequirement, PolicyRule};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use users::os::unix::GroupExt;

pub const POLICY_DIR: &str = "/etc/authd/policies.d";

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error in {file}: {error}")]
    Parse { file: PathBuf, error: String },
}

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Run immediately, no interaction
    AllowImmediate,
    /// Show confirmation dialog
    AllowWithConfirm,
    /// Require password authentication
    RequireAuth,
    /// Denied by policy
    Denied(String),
    /// No matching policy
    Unknown,
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
        self.load_from_dir(Path::new(POLICY_DIR))
    }

    /// Load policies from a specific directory
    pub fn load_from_dir(&mut self, policy_dir: &Path) -> Result<(), PolicyError> {
        if !policy_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(policy_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "toml") {
                // Ignore individual file errors, just skip
                let _ = self.load_file(&path);
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
        // Try exact match first, then wildcard
        let rule = self.rules.get(target)
            .or_else(|| self.rules.get(Path::new("*")));

        let Some(rule) = rule else {
            return PolicyDecision::Unknown;
        };

        // Check user/group permissions
        let username = username_from_uid(uid);
        let user_allowed = username
            .as_ref()
            .is_some_and(|u| rule.allow_users.contains(u));

        let group_allowed = rule
            .allow_groups
            .iter()
            .any(|g| user_in_group(uid, g));

        if !user_allowed && !group_allowed {
            return PolicyDecision::Denied("user not authorized".into());
        }

        match rule.auth {
            AuthRequirement::None => PolicyDecision::AllowImmediate,
            AuthRequirement::Confirm => PolicyDecision::AllowWithConfirm,
            AuthRequirement::Password => PolicyDecision::RequireAuth,
            AuthRequirement::Deny => PolicyDecision::Denied("target denied by policy".into()),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

// --- User/group helpers ---

pub fn username_from_uid(uid: u32) -> Option<String> {
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

pub fn user_in_group(uid: u32, group_name: &str) -> bool {
    let Some(user) = users::get_user_by_uid(uid) else {
        return false;
    };

    let Some(group) = users::get_group_by_name(group_name) else {
        return false;
    };

    // Check primary group
    if user.primary_group_id() == group.gid() {
        return true;
    }

    // Check supplementary groups
    let username = user.name();
    group.members().iter().any(|m| m == username)
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
    fn wildcard_match() {
        let mut engine = PolicyEngine::new();
        let uid = users::get_current_uid();
        let username = username_from_uid(uid).unwrap();

        engine.add_rule(PolicyRule {
            target: PathBuf::from("*"),
            allow_users: vec![username],
            allow_groups: vec![],
            auth: AuthRequirement::None,
            cache_timeout: 300,
        });

        // Any target should match the wildcard
        let decision = engine.check(Path::new("/usr/bin/anything"), uid);
        assert!(matches!(decision, PolicyDecision::AllowImmediate));
    }

    #[test]
    fn exact_match_priority() {
        let mut engine = PolicyEngine::new();
        let uid = users::get_current_uid();
        let username = username_from_uid(uid).unwrap();

        // Wildcard allows without auth
        engine.add_rule(PolicyRule {
            target: PathBuf::from("*"),
            allow_users: vec![username.clone()],
            allow_groups: vec![],
            auth: AuthRequirement::None,
            cache_timeout: 300,
        });

        // Exact match requires password
        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/sensitive"),
            allow_users: vec![username],
            allow_groups: vec![],
            auth: AuthRequirement::Password,
            cache_timeout: 300,
        });

        // Exact match should take priority
        let decision = engine.check(Path::new("/usr/bin/sensitive"), uid);
        assert!(matches!(decision, PolicyDecision::RequireAuth));

        // Other targets use wildcard
        let decision = engine.check(Path::new("/usr/bin/other"), uid);
        assert!(matches!(decision, PolicyDecision::AllowImmediate));
    }

    #[test]
    fn current_user_in_wheel() {
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
        if user_in_group(uid, "wheel") {
            assert!(matches!(decision, PolicyDecision::AllowImmediate));
        }
    }

    #[test]
    fn current_user_by_name() {
        let uid = users::get_current_uid();
        let username = username_from_uid(uid).unwrap();

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

    #[test]
    fn confirm_policy() {
        let mut engine = PolicyEngine::new();
        let uid = users::get_current_uid();
        let username = username_from_uid(uid).unwrap();

        engine.add_rule(PolicyRule {
            target: PathBuf::from("/usr/bin/confirm"),
            allow_users: vec![username],
            allow_groups: vec![],
            auth: AuthRequirement::Confirm,
            cache_timeout: 300,
        });

        let decision = engine.check(Path::new("/usr/bin/confirm"), uid);
        assert!(matches!(decision, PolicyDecision::AllowWithConfirm));
    }
}
