use librespot_core::{
    authentication::Credentials, cache::Cache, config::SessionConfig, session::Session,
};
use librespot_protocol::authentication::AuthenticationType;

/// Create reusable credentials
///
/// Reusable credentials are provided by Spotify. There are given back as
/// welcome data when establishing a new authenticated connection.
pub fn create_reusable_credentials(
    cache: Cache,
    credentials: Credentials,
) -> Result<Credentials, Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let session = Session::new(SessionConfig::default(), Some(cache.clone()));
            session.connect(credentials, true).await
        })?;

    // The reusable credentials are automatically saved in the cache. Reading
    // them back.
    cache
        .credentials()
        .ok_or_else(|| "There are no reusable credentials saved in cache".into())
}

/// Transform existing credentials into token credentials
pub fn change_to_token_credentials(
    credentials: Credentials,
) -> Result<Credentials, Box<dyn std::error::Error>> {
    let username = credentials.username.clone();

    // By default, use the clientID of the official Spotify client
    let token = get_token(credentials, "65b708073fc0480ea92a077233ca87bd", "streaming")?;

    Ok(Credentials {
        username,
        auth_type: AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN,
        auth_data: token.as_bytes().into(),
    })
}

/// Get the authentication token
pub fn get_token(
    credentials: Credentials,
    client_id: &str,
    scope: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let token = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let session = Session::new(SessionConfig::default(), None);
            session.set_client_id(client_id);
            let connection_result: Result<(), String> = session
                .connect(credentials, false)
                .await
                .map_err(|e| format!("Unable to create a Spotify session: {e}"));

            match connection_result {
                Ok(()) => session
                    .token_provider()
                    .get_token(scope)
                    .await
                    .map_err(|e| format!("Unable to get a token from the Spotify session: {e:?}")),
                Err(e) => Err(e),
            }
        })?;

    Ok(token.access_token)
}
