// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod error;
mod handlers;
mod models;

use handlers::imap::{connect_imap, fetch_emails, fetch_email_body};
// use handlers::account::{test_connection, save_account, get_accounts};
// use handlers::smtp::send_email;


fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            // IMAP handlers
            connect_imap,
            fetch_emails,
            fetch_email_body,
            // // SMTP handlers
            // send_email,
            // // Account handlers
            // test_connection,
            // save_account,
            // get_accounts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
