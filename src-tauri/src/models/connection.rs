use serde::{Serialize, Deserialize};
// REQUIREMENTS FOR ImapConfig STRUCT:
// 1. Configuration for RECEIVING emails via IMAP protocol, "What info do I need to log into imap.gmail.com?"
// 2. Used by your imap.rs handler to connect to email server
// 3. Needs: server hostname, port, email, password
// 4. Should NOT be Clone (contains credentials)
#[derive(Debug, Serialize, Deserialize)]
pub struct ImapConfig {
    pub hostname: String,
    pub port: u16,
    pub email: String,
    pub password: String,
}

// REQUIREMENTS FOR SmtpConfig STRUCT:
// 1. Configuration for SENDING emails via SMTP protocol
// 2. Used by your smtp.rs handler to send emails
// 3. Needs: server hostname, port, email, password
// 4. Should NOT be Clone (contains credentials)
// 5. Think: "What info do I need to send via smtp.gmail.com?"

pub struct SmtpConfig {
    pub hostname: String,
    pub port: u16,
    pub email: String,
    pub password: String,
}

// tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imap_config_creation() {
        let config = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 993,
            email: "user@gmail.com".to_string(),
            password: "secret123".to_string(),
        };

        assert_eq!(config.hostname, "imap.gmail.com");
        assert_eq!(config.port, 993);
        assert_eq!(config.email, "user@gmail.com");
        assert_eq!(config.password, "secret123");
    }

    #[test]
    fn test_smtp_config_creation() {
        let config = SmtpConfig {
            hostname: "smtp.gmail.com".to_string(),
            port: 587,
            email: "user@gmail.com".to_string(),
            password: "secret123".to_string(),
        };

        assert_eq!(config.hostname, "smtp.gmail.com");
        assert_eq!(config.port, 587);
        assert_eq!(config.email, "user@gmail.com");
        assert_eq!(config.password, "secret123");
    }
}