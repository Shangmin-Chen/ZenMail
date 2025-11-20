use serde::{Serialize, Deserialize};

// REQUIREMENTS FOR Email STRUCT:
// 1. Should represent a PREVIEW of an email (for inbox list)
// 2. Needs: id, subject, sender, recipients, date, preview text, read status
// 4. should all be public
// id, subject, from, date, preview are all text -> String, 
// Multiple recipients -> Vec<String> (a list of Strings)
// Read status is true/false -> bool
// Make it Clone-able so you can duplicate emails
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Email {
    pub id: String,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub preview: String,
    pub to: Vec<String>,
    pub is_read: bool,
}

// REQUIREMENTS FOR EmailBody STRUCT:
// 1. Should represent the FULL email content (when user clicks to read)
// 2. Needs all the metadata from Email + the actual body content
// 3. public
// Has plain text body (always exists) -> String
// Might have HTML body (not all emails have this) -> Option<String>
// Doesn't need to be Clone (we won't copy full email bodies around)
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailBody {
    pub id: String,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub preview: String,
    pub to: Vec<String>,
    pub is_read: bool,
    pub body_text: String,
    pub body_html: Option<String>, // this is the same as the Option type in OCaml, can be Some(data) or None
}

// Test (Claude generated)
#[cfg(test)]
mod tests {
    use super::*;  // Import Email and EmailBody from parent module
    
    #[test]
    fn test_email_creation() {
        let email = Email {
            id: "msg_001".to_string(),
            subject: "Hello".to_string(),
            from: "alice@example.com".to_string(),
            to: vec!["bob@example.com".to_string()],
            date: "2025-01-15T10:30:00Z".to_string(),
            preview: "Preview text".to_string(),
            is_read: false,
        };
        
        assert_eq!(email.id, "msg_001");
        assert_eq!(email.is_read, false);
    }
    
    #[test]
    fn test_email_clone() {
        let email = Email {
            id: "msg_002".to_string(),
            subject: "Test".to_string(),
            from: "test@test.com".to_string(),
            to: vec!["user@example.com".to_string()],
            date: "2025-01-15T10:30:00Z".to_string(),
            preview: "Test preview".to_string(),
            is_read: true,
        };
        
        let cloned = email.clone();
        assert_eq!(email.id, cloned.id);
        assert_eq!(email.subject, cloned.subject);
    }
    
    #[test]
    fn test_email_body_with_html() {
        let body = EmailBody {
            id: "msg_003".to_string(),
            subject: "HTML Email".to_string(),
            from: "sender@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            date: "2025-01-15T10:30:00Z".to_string(),
            preview: "Preview".to_string(),
            is_read: false,
            body_text: "Plain text body".to_string(),
            body_html: Some("<p>HTML body</p>".to_string()),
        };
        
        assert!(body.body_html.is_some());
    }
    
    #[test]
    fn test_email_body_without_html() {
        let body = EmailBody {
            id: "msg_004".to_string(),
            subject: "Plain Email".to_string(),
            from: "sender@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            date: "2025-01-15T10:30:00Z".to_string(),
            preview: "Preview".to_string(),
            is_read: false,
            body_text: "Just plain text".to_string(),
            body_html: None,  // No HTML version
        };
        
        assert!(body.body_html.is_none());
    }
}