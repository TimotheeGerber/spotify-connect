use std::{error, fmt, io::Write};

use clap::{ArgEnum, Parser};
use librespot_core::{authentication::Credentials, cache::Cache, diffie_hellman::DhLocalKeys};
use librespot_protocol::authentication::AuthenticationType;
use log::info;

use spotify_connect_client::{auth, net, proto};

/// Use the Spotify Connect feature to authenticate yourself on remote devices
#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// IP address of the remote device
    ip: std::net::IpAddr,

    /// Port on which the remote device is listening
    port: u16,

    /// Path to the ZeroConf API on the device web server
    #[clap(default_value = "/")]
    path: String,

    /// The authentication method to use
    #[clap(short, long, arg_enum, default_value_t)]
    auth_type: AuthType,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, ArgEnum)]
enum AuthType {
    #[default]
    Reusable,
    Password,
    DefaultToken,
    AccessToken,
}

/// Prompt the user for its Spotify username and password
fn ask_user_credentials() -> Result<Credentials, std::io::Error> {
    // Username
    print!("Spotify username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    username = username.trim_end().to_string();

    // Password
    let password = rpassword::prompt_password(format!("Password for {username}: "))?;

    Ok(Credentials {
        username,
        auth_type: AuthenticationType::AUTHENTICATION_USER_PASS,
        auth_data: password.as_bytes().into(),
    })
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

fn authenticate(
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

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    // Parse arguments
    let args = Args::parse();

    // Prepare cache
    let mut cache_path = dirs::cache_dir().expect("Impossible to find the user cache directory.");
    cache_path.push("spotify-connect");

    let cache = Cache::new(Some(cache_path.as_path()), None, None).unwrap_or_else(|e| {
        panic!(
            "Impossible to open cache path {}: {e}",
            cache_path.display()
        )
    });

    // Get credentials
    let credentials = match args.auth_type {
        AuthType::Reusable | AuthType::AccessToken => {
            cache.credentials().unwrap_or_else(|| {
                // Cache is empty, authenticate to create the credentials
                let credentials =
                    ask_user_credentials().expect("Getting username and password failed");
                auth::create_reusable_credentials(cache, credentials).unwrap_or_else(|e| {
                    panic!("Getting reusable credentials from spotify failed: {e}")
                })
            })
        }
        AuthType::Password => ask_user_credentials().expect("Getting username and password failed"),
        AuthType::DefaultToken => {
            let credentials = cache.credentials().unwrap_or_else(|| {
                ask_user_credentials().expect("Getting username and password failed")
            });

            auth::change_to_token_credentials(credentials)
                .unwrap_or_else(|e| panic!("Token retrieval failed: {e}"))
        }
    };

    let device_info = authenticate(
        &std::net::SocketAddr::new(args.ip, args.port),
        &args.path,
        &credentials,
        &args.auth_type,
    )
    .unwrap_or_else(|e| panic!("authentication failed: {e}"));

    println!(
        "🎉 Connected as `{}` on `{}` 🎉",
        credentials.username, device_info.remote_name
    );
}
