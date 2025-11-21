//! IMAP protocol handler for email operations.
//!
//! This module provides functionality for connecting to IMAP servers, fetching email
//! lists, and retrieving email content. All operations are asynchronous and designed
//! to be called as Tauri commands from the frontend.
//!
//! # Examples
//!
//! ```no_run
//! use zenmail::handlers::imap::connect_imap;
//! use zenmail::models::ImapConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ImapConfig {
//!     hostname: "imap.gmail.com".to_string(),
//!     port: 993,
//!     email: "user@example.com".to_string(),
//!     password: "app_password".to_string(),
//! };
//!
//! let result = connect_imap(config).await?;
//! println!("{}", result);
//! # Ok(())
//! # }
//! ```
use crate::error::EmailError;
use crate::models::{Email, EmailBody, ImapConfig};
use async_imap::Session;
use async_native_tls::TlsStream;
use futures::StreamExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use mailparse::MailHeaderMap;

/// Type alias for an authenticated IMAP session over TLS.
///
/// This represents a secure, authenticated connection to an IMAP server using:
/// - [`Session`]: async-imap session type
/// - [`TlsStream`]: Native TLS encryption layer
/// - [`tokio_util::compat::Compat`]: Compatibility layer between tokio and futures-io
type ImapSession = Session<TlsStream<tokio_util::compat::Compat<tokio::net::TcpStream>>>;

/// Creates and authenticates an IMAP session.
///
/// Establishes a secure TLS connection to the IMAP server and performs authentication
/// using the provided credentials. The connection goes through several stages:
///
/// 1. TCP connection establishment
/// 2. TLS handshake and encryption setup
/// 3. IMAP authentication with username/password
///
/// # Arguments
///
/// * `config` - IMAP server configuration containing connection details and credentials
///
/// # Returns
///
/// Returns an authenticated [`ImapSession`] on success, or an [`EmailError`] describing
/// the failure reason.
///
/// # Errors
///
/// This function will return an error if:
/// - TCP connection to the server fails ([`EmailError::ImapConnection`])
/// - TLS handshake fails ([`EmailError::ImapConnection`])
/// - Authentication is rejected ([`EmailError::AuthenticationFailed`])
///
/// # Examples
///
/// ```no_run
/// # use zenmail::handlers::imap::*;
/// # use zenmail::models::ImapConfig;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ImapConfig {
///     hostname: "imap.gmail.com".to_string(),
///     port: 993,
///     email: "user@gmail.com".to_string(),
///     password: "app_password".to_string(),
/// };
///
/// let session = create_imap_session(&config).await?;
/// # Ok(())
/// # }
/// ```
async fn create_imap_session(config: &ImapConfig) -> Result<ImapSession, EmailError> {
    let tls = async_native_tls::TlsConnector::new();
    
    let addr = format!("{}:{}", config.hostname, config.port);
    let tcp_stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| EmailError::ImapConnection(format!("TCP connection failed: {}", e)))?;
    
    let tcp_stream_compat = tcp_stream.compat();
    
    let tls_stream = tls
        .connect(&config.hostname, tcp_stream_compat)
        .await
        .map_err(|e| EmailError::ImapConnection(format!("TLS handshake failed: {}", e)))?;
    
    let client = async_imap::Client::new(tls_stream);
    
    let session = client
        .login(&config.email, &config.password)
        .await
        .map_err(|_| EmailError::AuthenticationFailed)?;

    Ok(session)
}

/// Tests IMAP server connectivity and authentication.
///
/// Validates that the provided credentials can successfully connect to the IMAP server
/// and access the INBOX folder. This is typically called before saving account credentials
/// to ensure they are valid.
///
/// This function performs the following checks:
/// 1. Establishes connection to the IMAP server
/// 2. Authenticates with provided credentials
/// 3. Attempts to select the INBOX folder
/// 4. Cleanly disconnects from the server
///
/// # Arguments
///
/// * `config` - IMAP configuration to test
///
/// # Returns
///
/// Returns `Ok(String)` with a success message if the connection is valid, or
/// `Err(String)` with a user-friendly error message describing the failure.
///
/// # Errors
///
/// This function will return an error if:
/// - The server cannot be reached
/// - Authentication fails (wrong username/password)
/// - The INBOX folder cannot be accessed
///
/// # Examples
///
/// From Rust:
/// ```no_run
/// # use zenmail::handlers::imap::connect_imap;
/// # use zenmail::models::ImapConfig;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ImapConfig {
///     hostname: "imap.gmail.com".to_string(),
///     port: 993,
///     email: "user@gmail.com".to_string(),
///     password: "app_password".to_string(),
/// };
///
/// match connect_imap(config).await {
///     Ok(msg) => println!("Success: {}", msg),
///     Err(err) => eprintln!("Failed: {}", err),
/// }
/// # Ok(())
/// # }
/// ```
///
/// From TypeScript (frontend):
/// ```typescript
/// import { invoke } from '@tauri-apps/api/core';
///
/// try {
///   const result = await invoke('connect_imap', {
///     config: {
///       hostname: 'imap.gmail.com',
///       port: 993,
///       email: 'user@gmail.com',
///       password: 'app_password'
///     }
///   });
///   console.log(result); // "Connection successful"
/// } catch (error) {
///   console.error('Connection failed:', error);
/// }
/// ```
#[tauri::command]
pub async fn connect_imap(config: ImapConfig) -> Result<String, String> {
    let mut session = create_imap_session(&config).await?;
    
    session
        .select("INBOX")
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    session
        .logout()
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    Ok("Connection successful".to_string())
}

/// Fetches email previews from a specified folder.
///
/// Retrieves metadata for emails in the specified folder without downloading full
/// message bodies. This is more efficient for displaying inbox lists as it only
/// fetches envelope information (from, to, subject, date) and flags (read status).
///
/// The function currently fetches the first 50 messages. This can be adjusted based
/// on requirements or made configurable in future versions.
///
/// # Arguments
///
/// * `account_id` - Unique identifier for the account to fetch from
/// * `folder` - Name of the folder to fetch (e.g., "INBOX", "Sent", "Trash")
///
/// # Returns
///
/// Returns `Ok(Vec<Email>)` containing email previews, or `Err(String)` with an
/// error message if the operation fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The account ID is not found in storage
/// - Connection to the IMAP server fails
/// - The specified folder does not exist
/// - There are issues reading message data
///
/// # IMAP Protocol Details
///
/// This function uses the following IMAP commands:
/// - `SELECT`: Opens the specified folder
/// - `FETCH 1:50 ENVELOPE FLAGS`: Retrieves metadata and flags for messages 1-50
///   - `ENVELOPE`: Contains from, to, subject, date, message-id
///   - `FLAGS`: Contains message flags like \Seen, \Answered, \Flagged
///
/// # Examples
///
/// From TypeScript:
/// ```typescript
/// import { invoke } from '@tauri-apps/api/core';
///
/// const emails = await invoke('fetch_emails', {
///   accountId: 'account-uuid-123',
///   folder: 'INBOX'
/// });
///
/// emails.forEach(email => {
///   console.log(`${email.from}: ${email.subject}`);
/// });
/// ```
///
/// # Performance
///
/// This function only fetches email metadata, not body content. For a folder with
/// 1000 messages, fetching 50 previews typically takes 1-3 seconds depending on
/// network latency.
///
/// # TODO
///
/// - Add pagination support for large mailboxes
/// - Make fetch limit configurable
/// - Add option to fetch most recent emails first
#[tauri::command]
pub async fn fetch_emails(
    account_id: String,
    folder: String,
) -> Result<Vec<Email>, String> {
    let config = get_account_config(&account_id).await?;
    
    let mut session = create_imap_session(&config).await?;
    
    session
        .select(&folder)
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    let mut messages_stream = session
        .fetch("1:50", "ENVELOPE FLAGS")
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    let mut emails = Vec::new();
    
    while let Some(fetch_result) = messages_stream.next().await {
        let msg = fetch_result
            .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
        
        if let Some(envelope) = msg.envelope() {
            // Extract from address
            let from = envelope
                .from
                .as_ref()
                .and_then(|addrs| addrs.first())
                .and_then(|addr| {
                    let mailbox = addr.mailbox.as_ref()?.as_ref();
                    let host = addr.host.as_ref()?.as_ref();
                    let mailbox_str = std::str::from_utf8(mailbox).ok()?;
                    let host_str = std::str::from_utf8(host).ok()?;
                    Some(format!("{}@{}", mailbox_str, host_str))
                })
                .unwrap_or_else(|| "Unknown".to_string());

            // Extract to addresses
            let to = envelope
                .to
                .as_ref()
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|addr| {
                            let mailbox = std::str::from_utf8(addr.mailbox.as_ref()?.as_ref()).ok()?;
                            let host = std::str::from_utf8(addr.host.as_ref()?.as_ref()).ok()?;
                            Some(format!("{}@{}", mailbox, host))
                        })
                        .collect()
                })
                .unwrap_or_default();

            let email = Email {
                id: msg.message.to_string(),
                subject: envelope
                    .subject
                    .as_ref()
                    .and_then(|s| std::str::from_utf8(s.as_ref()).ok())
                    .unwrap_or("(No Subject)")
                    .to_string(),
                from,
                date: envelope
                    .date
                    .as_ref()
                    .and_then(|d| std::str::from_utf8(d.as_ref()).ok())
                    .unwrap_or("")
                    .to_string(),
                preview: String::new(),
                to,
                is_read: msg.flags().any(|f| matches!(f, async_imap::types::Flag::Seen)),
            };
            emails.push(email);
        }
    }
    
    drop(messages_stream);
    
    session
        .logout()
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    Ok(emails)
}

/// Fetches the full content of a specific email.
///
/// Retrieves the complete email message including headers and body content in RFC822
/// format. This is called when a user opens an email to read it in full.
///
/// # Arguments
///
/// * `account_id` - Unique identifier for the account
/// * `email_id` - Message sequence number of the email to fetch
///
/// # Returns
///
/// Returns `Ok(EmailBody)` containing the full email content, or `Err(String)`
/// with an error message if the operation fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The account ID is not found in storage
/// - Connection to the IMAP server fails
/// - The email ID does not exist
/// - The email content cannot be parsed as UTF-8
///
/// # IMAP Protocol Details
///
/// Uses `FETCH <id> RFC822` to retrieve the complete message in RFC822 format,
/// which includes all headers and body content.
///
/// # Examples
///
/// From TypeScript:
/// ```typescript
/// import { invoke } from '@tauri-apps/api/core';
///
/// const emailBody = await invoke('fetch_email_body', {
///   accountId: 'account-uuid-123',
///   emailId: '42'
/// });
///
/// console.log(`Subject: ${emailBody.subject}`);
/// console.log(`Body: ${emailBody.body_text}`);
/// ```
///
/// # Performance
///
/// Fetching full email bodies is slower than fetching previews as it downloads
/// the entire message. Large emails with attachments can take several seconds.
///
/// # TODO
///
/// - Parse and expose additional email headers (Reply-To, Cc, Bcc, In-Reply-To)
/// - Support attachment extraction and metadata
/// - Handle edge cases in email address parsing (display names, UTF-8)
///
/// Retrieves the complete email message including headers and body content in RFC822
/// format, then parses it to extract all relevant fields including HTML and plain text.
#[tauri::command]
pub async fn fetch_email_body(
    account_id: String,
    email_id: String,
) -> Result<EmailBody, String> {
    let config = get_account_config(&account_id).await?;
    
    let mut session = create_imap_session(&config).await?;
    
    session
        .select("INBOX")
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    // Fetch both RFC822 (full content) and FLAGS (read status)
    let mut messages_stream = session
        .fetch(&email_id, "RFC822 FLAGS")
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    let msg = messages_stream
        .next()
        .await
        .ok_or_else(|| EmailError::EmailNotFound(email_id.clone()))?
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    // Get the raw RFC822 body
    let body = msg
        .body()
        .ok_or_else(|| EmailError::EmailNotFound(email_id.clone()))?;
    
    // Get read status from flags
    let is_read = msg.flags().any(|f| matches!(f, async_imap::types::Flag::Seen));
    
    // Parse the RFC822 email
    let parsed = mailparse::parse_mail(body)
        .map_err(|e| EmailError::ParseError(format!("Failed to parse email: {}", e)))?;
    
    // Extract headers
    let subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_else(|| "(No Subject)".to_string());
    
    let from = parsed
        .headers
        .get_first_value("From")
        .unwrap_or_else(|| "Unknown".to_string());
    
    let date = parsed
        .headers
        .get_first_value("Date")
        .unwrap_or_default();
    
    // Extract To addresses
    let to = parsed
        .headers
        .get_first_value("To")
        .map(|to_str| {
            // Simple split by comma - can be improved with proper email parsing
            to_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    
    // Extract body parts (both plain text and HTML)
    let (body_text, body_html) = extract_body_parts(&parsed);
    
    // Generate preview from plain text (first 200 chars)
    let preview = body_text
        .chars()
        .take(200)
        .collect::<String>()
        .trim()
        .to_string();
    
    let email_body = EmailBody {
        id: email_id,
        subject,
        from,
        date,
        preview,
        to,
        is_read,
        body_text,
        body_html,
    };
    
    drop(messages_stream);
    
    session
        .logout()
        .await
        .map_err(|e| EmailError::ImapConnection(e.to_string()))?;
    
    Ok(email_body)
}

/// Extracts plain text and HTML body parts from a parsed email.
///
/// Handles multipart MIME messages by recursively searching for text/plain
/// and text/html parts. Returns (plain_text, html_option).
fn extract_body_parts(parsed: &mailparse::ParsedMail) -> (String, Option<String>) {
    let mut plain_text = String::new();
    let mut html_text: Option<String> = None;
    
    // Recursive function to walk through all parts
    fn extract_parts(part: &mailparse::ParsedMail, plain: &mut String, html: &mut Option<String>) {
        match part.ctype.mimetype.as_str() {
            "text/plain" => {
                if let Ok(text) = part.get_body() {
                    if !plain.is_empty() {
                        plain.push_str("\n\n");
                    }
                    plain.push_str(&text);
                }
            }
            "text/html" => {
                if let Ok(text) = part.get_body() {
                    // Store the first HTML part we find
                    if html.is_none() {
                        *html = Some(text);
                    }
                }
            }
            // For multipart messages, recursively check subparts
            mime if mime.starts_with("multipart/") => {
                for subpart in &part.subparts {
                    extract_parts(subpart, plain, html);
                }
            }
            _ => {
                // Other content types (images, attachments, etc.) - ignore for now
            }
        }
    }
    
    extract_parts(parsed, &mut plain_text, &mut html_text);
    
    // If we didn't find any text/plain part, try to get body from the main part
    if plain_text.is_empty() {
        if let Ok(body) = parsed.get_body() {
            plain_text = body;
        }
    }
    
    (plain_text, html_text)
}

/// Retrieves IMAP configuration for a specific account.
///
/// Looks up the stored credentials and server settings for the given account ID.
/// This function is used internally by other handlers to get connection details.
///
/// # Arguments
///
/// * `account_id` - Unique identifier for the account
///
/// # Returns
///
/// Returns `Ok(ImapConfig)` with the account configuration, or `Err(String)`
/// if the account is not found.
///
/// # Errors
///
/// Returns [`EmailError::AccountNotFound`] if no account exists with the given ID.
///
/// # Security
///
/// When database storage is implemented, this function should:
/// - Decrypt stored credentials before returning
/// - Never log passwords
/// - Consider using OS keyring for credential storage
///
/// # Note
///
/// This is currently a placeholder that always returns an error. It will be
/// implemented when the database layer is added.
async fn get_account_config(account_id: &str) -> Result<ImapConfig, String> {
    // TODO: Replace with database lookup
    Ok(ImapConfig {
        hostname: "imap.gmail.com".to_string(),
        port: 993,
        email: std::env::var("TEST_GMAIL_EMAIL").map_err(|_| "Email not configured")?,
        password: std::env::var("TEST_GMAIL_APP_PASSWORD").map_err(|_| "Password not configured")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    /// Tests basic IMAP configuration struct creation.
    #[test]
    fn test_imap_config_creation() {
        let config = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 993,
            email: "test@gmail.com".to_string(),
            password: "secret".to_string(),
        };
        
        assert_eq!(config.hostname, "imap.gmail.com");
        assert_eq!(config.port, 993);
        assert_eq!(config.email, "test@gmail.com");
    }

    /// Tests that configurations for common email providers are valid.
    #[test]
    fn test_imap_config_common_providers() {
        // Gmail
        let gmail = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 993,
            email: "user@gmail.com".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(gmail.hostname, "imap.gmail.com");
        assert_eq!(gmail.port, 993);

        // Outlook
        let outlook = ImapConfig {
            hostname: "outlook.office365.com".to_string(),
            port: 993,
            email: "user@outlook.com".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(outlook.hostname, "outlook.office365.com");
        assert_eq!(outlook.port, 993);

        // iCloud
        let icloud = ImapConfig {
            hostname: "imap.mail.me.com".to_string(),
            port: 993,
            email: "user@icloud.com".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(icloud.hostname, "imap.mail.me.com");
    }

    /// Tests connection to a real Gmail account using environment variables.
    ///
    /// Requires `TEST_GMAIL_EMAIL` and `TEST_GMAIL_APP_PASSWORD` environment variables.
    #[tokio::test]
    async fn test_real_gmail_connection() {
        let email = std::env::var("TEST_GMAIL_EMAIL")
            .expect("TEST_GMAIL_EMAIL environment variable not set");
        
        let password = std::env::var("TEST_GMAIL_APP_PASSWORD")
            .expect("TEST_GMAIL_APP_PASSWORD environment variable not set");

        let password = password.replace(" ", "");

        let config = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 993,
            email,
            password,
        };
        
        let result = connect_imap(config).await;
        assert!(result.is_ok(), "Gmail connection failed: {:?}", result.err());
        assert_eq!(result.unwrap(), "Connection successful");
    }

    /// Tests that invalid credentials are properly rejected.
    #[tokio::test]
    async fn test_invalid_credentials() {
        let config = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 993,
            email: "invalid@gmail.com".to_string(),
            password: "wrong_password".to_string(),
        };

        let result = connect_imap(config).await;
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err();
        assert!(
            error_msg.contains("Authentication failed") || 
            error_msg.contains("connection")
        );
    }

    /// Tests behavior when connecting to a non-existent hostname.
    #[tokio::test]
    async fn test_invalid_hostname() {
        let config = ImapConfig {
            hostname: "nonexistent.server.invalid".to_string(),
            port: 993,
            email: "test@test.com".to_string(),
            password: "password".to_string(),
        };

        let result = connect_imap(config).await;
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("connection failed") || error_msg.contains("TCP"));
    }

    /// Tests behavior when using an incorrect port number.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_wrong_port() {
        let config = ImapConfig {
            hostname: "imap.gmail.com".to_string(),
            port: 12345, // Invalid port
            email: "test@gmail.com".to_string(),
            password: "password".to_string(),
        };

        // TCP connections to closed ports retry with exponential backoff,
        // taking 60-120s to timeout naturally. We limit to 5s for faster tests.
        let result = timeout(Duration::from_secs(5), connect_imap(config)).await;
        
        // Either timeout or connection error proves the port is invalid
        match result {
            Err(_) => {}, // Timeout is acceptable
            Ok(connect_result) => assert!(connect_result.is_err()),
        }
    }

    /// Tests that account config can be retrieved from environment variables.
    #[tokio::test]
    async fn test_get_account_config() {
        // Skip test if environment variables aren't set
        if std::env::var("TEST_GMAIL_EMAIL").is_err() {
            println!("Skipping test - TEST_GMAIL_EMAIL not set");
            return;
        }
        
        let result = get_account_config("any_id").await;
        assert!(result.is_ok(), "Failed to get account config: {:?}", result.err());
        
        let config = result.unwrap();
        assert_eq!(config.hostname, "imap.gmail.com");
        assert_eq!(config.port, 993);
    }

    /// Tests password sanitization (space removal).
    #[test]
    fn test_password_space_removal() {
        let password_with_spaces = "abcd efgh ijkl mnop";
        let password_clean = password_with_spaces.replace(" ", "");
        
        assert_eq!(password_clean, "abcdefghijklmnop");
        assert_eq!(password_clean.len(), 16);
    }

    /// Tests that config can be created with different email providers.
    #[test]
    fn test_different_email_providers() {
        let providers = vec![
            ("imap.gmail.com", 993),
            ("imap.mail.yahoo.com", 993),
            ("outlook.office365.com", 993),
            ("imap.mail.me.com", 993),
            ("imap.fastmail.com", 993),
        ];

        for (hostname, port) in providers {
            let config = ImapConfig {
                hostname: hostname.to_string(),
                port,
                email: format!("user@{}", hostname),
                password: "test".to_string(),
            };
            
            assert_eq!(config.hostname, hostname);
            assert_eq!(config.port, port);
        }
    }
}