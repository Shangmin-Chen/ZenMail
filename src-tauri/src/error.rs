use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmailError {
    #[error("IMAP connection failed: {0}")]
    ImapConnection(String),
    
    #[error("SMTP connection failed: {0}")]
    SmtpConnection(String),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    
    #[error("Email not found: {0}")]
    EmailNotFound(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
}

impl From<EmailError> for String {
    fn from(error: EmailError) -> Self {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_to_string() {
        let err = EmailError::AuthenticationFailed;
        assert_eq!(err.to_string(), "Authentication failed");
    }

    #[test]
    fn test_error_with_context() {
        let err = EmailError::AccountNotFound("test123".to_string());
        assert!(err.to_string().contains("test123"));
    }
}