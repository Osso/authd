use pam::Client;
use thiserror::Error;
use users::os::unix::GroupExt;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AuthError {
    #[error("authentication failed")]
    Failed,
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("pam error: {0}")]
    Pam(String),
}

/// Authenticate a user with their password via PAM
#[allow(dead_code)]
pub fn authenticate(username: &str, password: &str) -> Result<(), AuthError> {
    let mut client = Client::with_password("authd")
        .map_err(|e| AuthError::Pam(e.to_string()))?;

    client
        .conversation_mut()
        .set_credentials(username, password);

    client.authenticate().map_err(|_| AuthError::Failed)?;
    client.open_session().map_err(|e| AuthError::Pam(e.to_string()))?;

    Ok(())
}

/// Get username from UID
pub fn username_from_uid(uid: u32) -> Option<String> {
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

/// Check if user is in a group
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
