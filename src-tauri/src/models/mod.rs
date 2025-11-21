pub mod account;
pub mod connection;
pub mod email;

// Remove the unused wildcard import
pub use account::{Account, AccountConfig};
pub use connection::{ImapConfig, SmtpConfig};
pub use email::{Email, EmailBody};