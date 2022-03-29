use librespot_core::{
    authentication::Credentials, cache::Cache, config::SessionConfig, keymaster, session::Session,
};
use librespot_protocol::authentication::AuthenticationType;
use std::io::Write;

/// Prompt the user for its Spotify username and password
pub fn ask_user_credentials() -> Result<Credentials, std::io::Error> {
    // Username
    print!("Spotify username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    username = username.trim_end().to_string();

    // Password
    let password = rpassword::prompt_password(&format!("Password for {username}: "))?;

    Ok(Credentials {
        username,
        auth_type: AuthenticationType::AUTHENTICATION_USER_PASS,
        auth_data: password.as_bytes().into(),
    })
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
    let credentials = ask_user_credentials()?;

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

/// Transform existing credentials into token credentials
pub fn change_to_token_credentials(
    credentials: Credentials,
) -> Result<Credentials, Box<dyn std::error::Error>> {
    let username = credentials.username.clone();

    let token = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let session = Session::connect(SessionConfig::default(), credentials, None)
                .await
                .expect("Impossible to create a Spotify session");

            keymaster::get_token(&session, "65b708073fc0480ea92a077233ca87bd", "streaming")
                .await
                .expect("Impossible to get a token from the Spotify session")
        });

    Ok(Credentials {
        username,
        auth_type: AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN,
        auth_data: token.access_token.as_bytes().into(),
    })
}
