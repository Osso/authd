use pam::Client;
use thiserror::Error;

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
