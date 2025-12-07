//! authsudo - setuid sudo replacement
//!
//! A minimal setuid binary that:
//! 1. Gets the real UID of the caller
//! 2. Checks policies
//! 3. Authenticates if required
//! 4. exec() the target command

use authd_protocol::{AuthRequirement, PolicyRule};
use pam::Client;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use users::os::unix::GroupExt;

const POLICY_DIR: &str = "/etc/authd/policies.d";

fn main() {
    // Get real UID (who invoked us, not effective UID which is root)
    let real_uid = unsafe { libc::getuid() };

    // Parse arguments
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: authsudo <command> [args...]");
        process::exit(1);
    }

    let target = PathBuf::from(&args[0]);
    let target_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    // Resolve to absolute path
    let target = resolve_path(&target).unwrap_or_else(|| {
        eprintln!("authsudo: command not found: {}", args[0]);
        process::exit(127);
    });

    // Load policies
    let mut engine = PolicyEngine::new();
    if let Err(e) = engine.load() {
        eprintln!("authsudo: failed to load policies: {}", e);
        process::exit(1);
    }

    // Check policy
    match engine.check(&target, real_uid) {
        PolicyDecision::Allow => {
            // Allowed without auth
        }
        PolicyDecision::RequireAuth => {
            // Need password authentication
            let username = username_from_uid(real_uid).unwrap_or_else(|| {
                eprintln!("authsudo: unknown user");
                process::exit(1);
            });

            if !authenticate_user(&username) {
                eprintln!("authsudo: authentication failed");
                process::exit(1);
            }
        }
        PolicyDecision::Denied(reason) => {
            eprintln!("authsudo: {}", reason);
            process::exit(1);
        }
        PolicyDecision::Unknown => {
            eprintln!("authsudo: no policy for {}", target.display());
            process::exit(1);
        }
    }

    // Drop back to root (we're setuid root, effective UID is already 0)
    // Set real UID to 0 as well for the exec
    unsafe {
        libc::setgid(0);
        libc::setuid(0);
    }

    // exec the target - this replaces our process
    let err = Command::new(&target).args(&target_args).exec();

    // If we get here, exec failed
    eprintln!("authsudo: failed to execute {}: {}", target.display(), err);
    process::exit(126);
}

/// Resolve a command to its absolute path
fn resolve_path(cmd: &Path) -> Option<PathBuf> {
    if cmd.is_absolute() {
        if cmd.exists() {
            return Some(cmd.to_path_buf());
        }
        return None;
    }

    // Search PATH
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let full = PathBuf::from(dir).join(cmd);
            if full.exists() {
                return Some(full);
            }
        }
    }

    None
}

/// Authenticate user via PAM
fn authenticate_user(username: &str) -> bool {
    // Read password from terminal
    let password = match rpassword::prompt_password(format!("[authsudo] password for {}: ", username)) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // PAM authentication
    let Ok(mut client) = Client::with_password("authd") else {
        return false;
    };

    client
        .conversation_mut()
        .set_credentials(username, &password);

    client.authenticate().is_ok()
}

// --- Policy Engine (minimal inline implementation) ---

struct PolicyEngine {
    rules: HashMap<PathBuf, PolicyRule>,
}

#[derive(Debug)]
enum PolicyDecision {
    Allow,
    RequireAuth,
    Denied(String),
    Unknown,
}

impl PolicyEngine {
    fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    fn load(&mut self) -> Result<(), String> {
        let policy_dir = Path::new(POLICY_DIR);
        if !policy_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(policy_dir).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "toml") {
                let _ = self.load_file(&path);
            }
        }

        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<(), String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let config: PolicyFile = toml::from_str(&content).map_err(|e| e.to_string())?;

        for rule in config.rules {
            self.rules.insert(rule.target.clone(), rule);
        }

        Ok(())
    }

    fn check(&self, target: &Path, uid: u32) -> PolicyDecision {
        let Some(rule) = self.rules.get(target) else {
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
            AuthRequirement::None => PolicyDecision::Allow,
            AuthRequirement::Password => PolicyDecision::RequireAuth,
            AuthRequirement::Deny => PolicyDecision::Denied("denied by policy".into()),
        }
    }
}

#[derive(serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

// --- User/group helpers ---

fn username_from_uid(uid: u32) -> Option<String> {
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

fn user_in_group(uid: u32, group_name: &str) -> bool {
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
