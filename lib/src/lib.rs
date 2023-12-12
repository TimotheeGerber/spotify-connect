use std::{error, fmt};

use librespot_core::{authentication::Credentials, diffie_hellman::DhLocalKeys};
use log::info;

pub mod auth;
pub mod net;
pub mod proto;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AuthType {
    #[default]
    Reusable,
    Password,
    DefaultToken,
    AccessToken,
}

#[derive(Debug)]
pub enum Error {
    CouldNotGetDeviceInfo(String, Box<dyn error::Error>),
    CouldNotAddUser(Box<dyn error::Error>),
    EncryptionFailed(Box<dyn error::Error>),
    MissingClientId,
    AccessTokenRetrievalFailure(Box<dyn error::Error>),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CouldNotGetDeviceInfo(base_url, e) => f.write_fmt(format_args!(
                "Could not get device information from {base_url}: {e}"
            )),
            Error::CouldNotAddUser(e) => f.write_fmt(format_args!(
                "Authentication on the remote remote device failed: {e}"
            )),
            Error::EncryptionFailed(e) => {
                f.write_fmt(format_args!("Encryption of credentials failed: {e}"))
            }
            Error::MissingClientId => f.write_str(
                "To authenticate with an access token, the remote device should provide a clientID",
            ),
            Error::AccessTokenRetrievalFailure(e) => f.write_fmt(format_args!(
                "The access token could not be retrieved from Spotify: {e}"
            )),
        }
    }
}

pub fn authenticate(
    sock_addr: &std::net::SocketAddr,
    path: &str,
    credentials: &Credentials,
    auth_type: &AuthType,
) -> Result<net::DeviceInfo, Error> {
    let base_url = format!("http://{}:{}{path}", sock_addr.ip(), sock_addr.port());

    // Get device information
    let device_info = net::get_device_info(&base_url)
        .map_err(|e| Error::CouldNotGetDeviceInfo(base_url.clone(), e))?;
    info!("Found `{}`. Trying to connect...", device_info.remote_name);

    let (blob, my_public_key) = match auth_type {
        AuthType::Reusable | AuthType::Password | AuthType::DefaultToken => {
            // Generate the blob
            let blob = proto::build_blob(credentials, &device_info.device_id);

            // Encrypt the blob
            let local_keys = DhLocalKeys::random(&mut rand::thread_rng());
            let encrypted_blob = proto::encrypt_blob(&blob, &local_keys, &device_info.public_key)
                .map_err(Error::EncryptionFailed)?;

            (encrypted_blob, base64::encode(local_keys.public_key()))
        }
        AuthType::AccessToken => {
            let client_id = device_info
                .client_id
                .as_deref()
                .ok_or(Error::MissingClientId)?;
            let scope = device_info.scope.as_deref().unwrap_or("streaming");

            let token = auth::get_token(credentials.clone(), client_id, scope)
                .map_err(Error::AccessTokenRetrievalFailure)?;

            (token, "".to_string())
        }
    };

    let token_type = match auth_type {
        AuthType::Reusable | AuthType::Password => None,
        AuthType::DefaultToken => Some("default"),
        AuthType::AccessToken => Some("accesstoken"),
    };

    // Send the authentication request
    net::add_user(
        &base_url,
        &credentials.username,
        &blob,
        &my_public_key,
        token_type,
    )
    .map_err(Error::CouldNotAddUser)?;

    Ok(device_info)
}
