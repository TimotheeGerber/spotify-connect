use librespot_core::{
    authentication::Credentials, cache::Cache, config::SessionConfig, session::Session,
};
use std::io::Write;

/// Prompt the user for its Spotify username and password
fn ask_user_credentials() -> Result<(String, String), std::io::Error> {
    // Username
    print!("Spotify username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    username = username.trim_end().to_string();

    // Password
    let password = rpassword::prompt_password(&format!("Password for {username}: "))?;

    Ok((username, password))
}

/// Create reusable credentials
///
/// Reusable credentials are provided by Spotify. There are given back as
/// welcome data when establishing a new authenticated connection. Even when
/// the user authenticate with the username/password couple.
pub fn create_reusable_credentials(
    cache: Cache,
) -> Result<Credentials, Box<dyn std::error::Error>> {
    // Authenticate with username/password
    let (username, password) = ask_user_credentials()?;
    let credentials = Credentials::with_password(username, password);

    let connection = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            Session::connect(SessionConfig::default(), credentials, Some(cache.clone())).await
        });

    connection?;

    // The reusable credentials are automatically saved in the cache. Reading
    // them back.
    cache
        .credentials()
        .ok_or_else(|| "There is no reusable credentials saved in cache".into())
}
