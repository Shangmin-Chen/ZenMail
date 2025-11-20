use serde::{Serialize, Deserialize};

// REQUIREMENTS FOR Account STRUCT:
// 1. Represents a user's email account (the "identity")
// 2. This is what you SHOW in the UI (account switcher, sidebar)
// 3. Does NOT include passwords or server details (security!)
// 4. Needs: id, email address, display name
// 5. Should be Clone-able (you'll pass this around a lot)
// 6. Think: "What info is safe to show in the frontend?"
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub display_name: String,
}

// REQUIREMENTS FOR AccountConfig STRUCT:
// 1. Represents HOW to connect to an email account, "What does my app need to log into Gmail/Outlook?"
// 2. This includes SENSITIVE data (password, server addresses)
// 3. Used by your IMAP/SMTP handlers to log in
// 4. Needs: email, password, IMAP server/port, SMTP server/port
// 5. Should NOT be Clone (contains sensitive data) 

// - Email, password, hostnames are text → String
// - Port numbers are 0-65535 → u16

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountConfig {
    pub email: String,
    pub password: String,
    pub imap_host: String,
    pub smtp_host: String,
    pub imap_port: u16,
    pub smtp_port: u16,
}

// test
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_account() {
        let account = Account {
            id: "acc_001".to_string(),
            email: "test@example.com".to_string(),
            display_name: "Test Account".to_string(),
        };
        
        // Should be able to clone
        let cloned = account.clone();
        assert_eq!(account.email, cloned.email);
    }
    
    #[test]
    fn test_create_config() {
        let config = AccountConfig {
            email: "user@gmail.com".to_string(),
            password: "secret".to_string(),
            imap_host: "imap.gmail.com".to_string(),
            imap_port: 993,
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
        };
        
        assert_eq!(config.imap_port, 993);
        assert_eq!(config.smtp_port, 587);
        
        // Try uncommenting below - should NOT compile!
        // let cloned = config.clone();  // Error: AccountConfig doesn't implement Clone
    }
    
    #[test]
    fn test_gmail_ports() {
        // Gmail's standard ports
        let config = AccountConfig {
            email: "user@gmail.com".to_string(),
            password: "app-password".to_string(),
            imap_host: "imap.gmail.com".to_string(),
            imap_port: 993,  // IMAP over SSL
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,  // SMTP with STARTTLS
        };
        
        assert_eq!(config.imap_port, 993);
    }
}