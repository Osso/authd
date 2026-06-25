use authd_protocol::{AuthRequirement, PolicyRule};
use glob::Pattern;
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
    /// Denied by policy
    Denied(String),
    /// No matching policy
    Unknown,
}

/// Caller info for policy checking
#[derive(Debug, Clone)]
pub struct CallerInfo<'a> {
    pub exe: &'a Path,
    /// Full resolved path of cmdline arg0 (for scripts run via interpreters)
    pub cmdline_path: Option<&'a Path>,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: HashMap<PathBuf, Vec<PolicyRule>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule directly (useful for testing)
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules
            .entry(rule.target.clone())
            .or_default()
            .push(rule);
    }

    /// Load policies from TOML string
    pub fn load_from_str(&mut self, content: &str) -> Result<usize, PolicyError> {
        let config: PolicyFile = toml::from_str(content).map_err(|e| PolicyError::Parse {
            file: PathBuf::from("<string>"),
            error: e.to_string(),
        })?;

        let count = config.rules.len();
        for rule in config.rules {
            self.rules
                .entry(rule.target.clone())
                .or_default()
                .push(rule);
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
        let config: PolicyFile = toml::from_str(&content).map_err(|e| PolicyError::Parse {
            file: path.to_path_buf(),
            error: e.to_string(),
        })?;

        let count = config.rules.len();
        for rule in config.rules {
            self.rules
                .entry(rule.target.clone())
                .or_default()
                .push(rule);
        }

        Ok(count)
    }

    /// Check if a user is authorized to run a target
    pub fn check(&self, target: &Path, uid: u32) -> PolicyDecision {
        self.check_with_caller(target, uid, None)
    }

    /// Check with caller info (single caller, for backwards compatibility)
    pub fn check_with_caller(
        &self,
        target: &Path,
        uid: u32,
        caller_exe: Option<&Path>,
    ) -> PolicyDecision {
        let callers: Vec<CallerInfo> = caller_exe
            .into_iter()
            .map(|exe| CallerInfo {
                exe,
                cmdline_path: None,
            })
            .collect();
        self.check_with_callers(target, uid, &callers)
    }

    /// Check with multiple callers (ancestor chain with exe and cmdline)
    pub fn check_with_callers(
        &self,
        target: &Path,
        uid: u32,
        callers: &[CallerInfo],
    ) -> PolicyDecision {
        let matching_rules = matching_rules(&self.rules, target);
        if matching_rules.is_empty() {
            return PolicyDecision::Unknown;
        }

        let username = username_from_uid(uid);
        let mut best_auth: Option<&AuthRequirement> = None;

        for rule in matching_rules {
            if !rule_allows(rule, uid, username.as_deref(), callers) {
                continue;
            }
            if matches!(rule.auth, AuthRequirement::None) {
                return PolicyDecision::AllowImmediate;
            }
            update_best_auth(&mut best_auth, &rule.auth);
        }

        match best_auth {
            Some(AuthRequirement::None) => PolicyDecision::AllowImmediate,
            Some(AuthRequirement::Confirm | AuthRequirement::Password) => {
                PolicyDecision::AllowWithConfirm
            }
            Some(AuthRequirement::Deny) => PolicyDecision::Denied("target denied by policy".into()),
            None => PolicyDecision::Denied("user not authorized".into()),
        }
    }
}

fn matching_rules<'a>(
    rules: &'a HashMap<PathBuf, Vec<PolicyRule>>,
    target: &Path,
) -> Vec<&'a PolicyRule> {
    let mut matches = Vec::new();
    if let Some(exact_rules) = rules.get(target) {
        matches.extend(exact_rules);
    }
    if let Some(wildcard_rules) = rules.get(Path::new("*")) {
        matches.extend(wildcard_rules);
    }
    matches
}

fn rule_allows(
    rule: &PolicyRule,
    uid: u32,
    username: Option<&str>,
    callers: &[CallerInfo],
) -> bool {
    user_allowed(rule, username) || group_allowed(rule, uid) || caller_allowed(rule, callers)
}

fn user_allowed(rule: &PolicyRule, username: Option<&str>) -> bool {
    username.is_some_and(|username| rule.allow_users.iter().any(|user| user == username))
}

fn group_allowed(rule: &PolicyRule, uid: u32) -> bool {
    rule.allow_groups
        .iter()
        .any(|group| user_in_group(uid, group))
}

fn caller_allowed(rule: &PolicyRule, callers: &[CallerInfo]) -> bool {
    callers
        .iter()
        .any(|caller| caller_matches_rule(rule, caller))
}

fn caller_matches_rule(rule: &PolicyRule, caller: &CallerInfo) -> bool {
    rule.allow_callers.iter().any(|allowed| {
        path_matches_pattern(caller.exe, allowed)
            || caller
                .cmdline_path
                .is_some_and(|path| path_matches_pattern(path, allowed))
    })
}

fn update_best_auth<'a>(
    best_auth: &mut Option<&'a AuthRequirement>,
    candidate: &'a AuthRequirement,
) {
    let dominated = best_auth.is_some_and(|best| auth_priority(candidate) >= auth_priority(best));
    if !dominated {
        *best_auth = Some(candidate);
    }
}

fn auth_priority(auth: &AuthRequirement) -> u8 {
    match auth {
        AuthRequirement::None => 0,
        AuthRequirement::Confirm => 1,
        AuthRequirement::Password => 2,
        AuthRequirement::Deny => 3,
    }
}

/// Check if a path matches a pattern (exact match or glob pattern)
fn path_matches_pattern(path: &Path, pattern: &Path) -> bool {
    // Exact match
    if path == pattern {
        return true;
    }
    // Glob pattern match (only if pattern contains glob chars)
    let pattern_str = pattern.to_string_lossy();
    if pattern_str.contains('*') || pattern_str.contains('?') || pattern_str.contains('[') {
        if let Ok(glob) = Pattern::new(&pattern_str) {
            return glob.matches_path(path);
        }
    }
    false
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
mod tests;
