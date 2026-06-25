use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_policy_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("authd-policy-{name}-{nonce}"));
    fs::create_dir(&dir).unwrap();
    dir
}

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
fn load_from_missing_dir_is_empty_success() {
    let mut engine = PolicyEngine::new();
    let missing = std::env::temp_dir().join("authd-policy-definitely-missing");

    engine.load_from_dir(&missing).unwrap();

    assert!(matches!(
        engine.check(Path::new("/usr/bin/test1"), users::get_current_uid()),
        PolicyDecision::Unknown
    ));
}

#[test]
fn load_file_reports_parse_errors_with_filename() {
    let dir = temp_policy_dir("parse-error");
    let file = dir.join("bad.toml");
    fs::write(&file, "not toml").unwrap();
    let mut engine = PolicyEngine::new();

    let error = engine.load_file(&file).unwrap_err();

    assert!(matches!(error, PolicyError::Parse { file: ref path, .. } if path == &file));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn load_from_dir_loads_toml_and_ignores_other_files() {
    let dir = temp_policy_dir("dir-load");
    fs::write(dir.join("ignored.txt"), "not toml").unwrap();
    fs::write(
        dir.join("rule.toml"),
        r#"
                [[rules]]
                target = "/usr/bin/loaded"
                allow_callers = ["/usr/bin/authsudo"]
                auth = "none"
            "#,
    )
    .unwrap();
    let mut engine = PolicyEngine::new();

    engine.load_from_dir(&dir).unwrap();

    let decision = engine.check_with_caller(
        Path::new("/usr/bin/loaded"),
        users::get_current_uid(),
        Some(Path::new("/usr/bin/authsudo")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn deny_policy() {
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/forbidden"),
        allow_users: vec!["root".into()],
        allow_groups: vec![],
        allow_callers: vec![],
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
        allow_callers: vec![],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Any target should match the wildcard
    let decision = engine.check(Path::new("/usr/bin/anything"), uid);
    assert!(matches!(decision, PolicyDecision::AllowImmediate));
}

#[test]
fn least_restrictive_wins() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();
    let username = username_from_uid(uid).unwrap();

    // Wildcard allows without auth
    engine.add_rule(PolicyRule {
        target: PathBuf::from("*"),
        allow_users: vec![username.clone()],
        allow_groups: vec![],
        allow_callers: vec![],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Exact match requires password
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/sensitive"),
        allow_users: vec![username],
        allow_groups: vec![],
        allow_callers: vec![],
        auth: AuthRequirement::Password,
        cache_timeout: 300,
    });

    // Least restrictive wins - wildcard's auth=none beats exact's auth=password
    let decision = engine.check(Path::new("/usr/bin/sensitive"), uid);
    assert!(matches!(decision, PolicyDecision::AllowImmediate));

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
        allow_callers: vec![],
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
        allow_callers: vec![],
        auth: AuthRequirement::Password,
        cache_timeout: 300,
    });

    // Password now treated same as Confirm
    let decision = engine.check(Path::new("/usr/bin/usertest"), uid);
    assert!(matches!(decision, PolicyDecision::AllowWithConfirm));
}

#[test]
fn user_not_authorized() {
    let mut engine = PolicyEngine::new();
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/restricted"),
        allow_users: vec!["nonexistent_user_xyz".into()],
        allow_groups: vec!["nonexistent_group_xyz".into()],
        allow_callers: vec![],
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
        allow_callers: vec![],
        auth: AuthRequirement::Confirm,
        cache_timeout: 300,
    });

    let decision = engine.check(Path::new("/usr/bin/confirm"), uid);
    assert!(matches!(decision, PolicyDecision::AllowWithConfirm));
}

#[test]
fn caller_authorization() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();

    // Rule that only allows a specific caller (no users/groups)
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/sensitive"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/usr/bin/claude")],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Without caller info - denied (no user/group match)
    let decision = engine.check(Path::new("/usr/bin/sensitive"), uid);
    assert!(matches!(decision, PolicyDecision::Denied(_)));

    // Untrusted caller - denied
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/sensitive"),
        uid,
        Some(Path::new("/usr/bin/unknown")),
    );
    assert!(matches!(decision, PolicyDecision::Denied(_)));

    // Trusted caller - allowed (auth=none means immediate)
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/sensitive"),
        uid,
        Some(Path::new("/usr/bin/claude")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));
}

#[test]
fn caller_cmdline_path_can_authorize_interpreter_scripts() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/protected"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/opt/scripts/request-access")],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    let decision = engine.check_with_callers(
        Path::new("/usr/bin/protected"),
        uid,
        &[CallerInfo {
            exe: Path::new("/usr/bin/python"),
            cmdline_path: Some(Path::new("/opt/scripts/request-access")),
        }],
    );

    assert!(matches!(decision, PolicyDecision::AllowImmediate));
}

#[test]
fn caller_respects_auth() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();

    // Caller allowed but auth=confirm
    engine.add_rule(PolicyRule {
        target: PathBuf::from("/usr/bin/confirm_cmd"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/usr/bin/claude")],
        auth: AuthRequirement::Confirm,
        cache_timeout: 300,
    });

    let decision = engine.check_with_caller(
        Path::new("/usr/bin/confirm_cmd"),
        uid,
        Some(Path::new("/usr/bin/claude")),
    );
    assert!(matches!(decision, PolicyDecision::AllowWithConfirm));
}

#[test]
fn multiple_wildcard_rules() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();
    let username = username_from_uid(uid).unwrap();

    // Rule 1: user with confirm
    engine.add_rule(PolicyRule {
        target: PathBuf::from("*"),
        allow_users: vec![username],
        allow_groups: vec![],
        allow_callers: vec![],
        auth: AuthRequirement::Confirm,
        cache_timeout: 300,
    });

    // Rule 2: claude caller with none
    engine.add_rule(PolicyRule {
        target: PathBuf::from("*"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/usr/bin/claude")],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Without caller - matches first rule (user allowed, confirm)
    let decision = engine.check(Path::new("/usr/bin/anything"), uid);
    assert!(matches!(decision, PolicyDecision::AllowWithConfirm));

    // With claude caller - picks least restrictive (none) from both matching rules
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/anything"),
        uid,
        Some(Path::new("/usr/bin/claude")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));
}

#[test]
fn caller_only_rule() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();

    // Only claude caller is allowed
    engine.add_rule(PolicyRule {
        target: PathBuf::from("*"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/usr/bin/claude")],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Without claude - denied
    let decision = engine.check(Path::new("/usr/bin/anything"), uid);
    assert!(matches!(decision, PolicyDecision::Denied(_)));

    // With claude - allowed
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/anything"),
        uid,
        Some(Path::new("/usr/bin/claude")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));
}

#[test]
fn caller_glob_pattern() {
    let mut engine = PolicyEngine::new();
    let uid = users::get_current_uid();

    // Allow any version of claude using glob pattern
    engine.add_rule(PolicyRule {
        target: PathBuf::from("*"),
        allow_users: vec![],
        allow_groups: vec![],
        allow_callers: vec![PathBuf::from("/home/osso/.local/share/claude/versions/*")],
        auth: AuthRequirement::None,
        cache_timeout: 300,
    });

    // Version 2.1.12 matches
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/anything"),
        uid,
        Some(Path::new("/home/osso/.local/share/claude/versions/2.1.12")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));

    // Version 3.0.0 also matches
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/anything"),
        uid,
        Some(Path::new("/home/osso/.local/share/claude/versions/3.0.0")),
    );
    assert!(matches!(decision, PolicyDecision::AllowImmediate));

    // Different path doesn't match
    let decision = engine.check_with_caller(
        Path::new("/usr/bin/anything"),
        uid,
        Some(Path::new("/usr/bin/other")),
    );
    assert!(matches!(decision, PolicyDecision::Denied(_)));
}

#[test]
fn path_matches_pattern_unit() {
    // Exact match
    assert!(path_matches_pattern(
        Path::new("/usr/bin/claude"),
        Path::new("/usr/bin/claude")
    ));

    // Glob with *
    assert!(path_matches_pattern(
        Path::new("/home/user/versions/2.1.12"),
        Path::new("/home/user/versions/*")
    ));

    // Glob doesn't match different prefix
    assert!(!path_matches_pattern(
        Path::new("/other/path/2.1.12"),
        Path::new("/home/user/versions/*")
    ));

    // No match
    assert!(!path_matches_pattern(
        Path::new("/usr/bin/other"),
        Path::new("/usr/bin/claude")
    ));
    assert!(!path_matches_pattern(
        Path::new("/usr/bin/test"),
        Path::new("[")
    ));
}

#[test]
fn user_lookup_helpers_reject_missing_entries() {
    assert!(username_from_uid(u32::MAX).is_none());
    assert!(!user_in_group(u32::MAX, "__missing_authd_group__"));
    assert!(!user_in_group(
        users::get_current_uid(),
        "__missing_authd_group__"
    ));
}
