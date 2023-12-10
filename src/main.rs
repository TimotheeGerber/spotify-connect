use std::io::Write;

use clap::{ArgEnum, Parser};
use librespot_core::{authentication::Credentials, cache::Cache, diffie_hellman::DhLocalKeys};
use librespot_protocol::authentication::AuthenticationType;

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

#[derive(Clone, Debug, PartialEq, Eq, ArgEnum)]
enum AuthType {
    Reusable,
    Password,
    DefaultToken,
    AccessToken,
}

impl Default for AuthType {
    fn default() -> AuthType {
        AuthType::Reusable
    }
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
    let password = rpassword::prompt_password(&format!("Password for {username}: "))?;

    Ok(Credentials {
        username,
        auth_type: AuthenticationType::AUTHENTICATION_USER_PASS,
        auth_data: password.as_bytes().into(),
    })
}

fn main() {
    // Parse arguments
    let args = Args::parse();
    let base_url = format!("http://{}:{}{}", args.ip, args.port, args.path);
    let mut token_type = None;

    // Get device information
    let device_info = net::get_device_info(&base_url)
        .unwrap_or_else(|_| panic!("Impossible to get device information from {base_url}"));
    println!("Found `{}`. Trying to connect...", device_info.remote_name);

    // Prepare cache
    let mut cache_path = dirs::cache_dir().expect("Impossible to find the user cache directory.");
    cache_path.push("spotify-connect");

    let cache = Cache::new(Some(cache_path), None, None)
        .expect("Impossible to open cache path: {cache_path}");

    // Get credentials
    let credentials = match args.auth_type {
        AuthType::Reusable | AuthType::AccessToken => {
            cache.credentials().unwrap_or_else(|| {
                // Cache is empty, authenticate to create the credentials
                let credentials = ask_user_credentials().expect("Getting username and password failed");
                auth::create_reusable_credentials(cache, credentials)
                    .expect("Getting reusable credentials from spotify failed")
            })
        }
        AuthType::Password => {
            ask_user_credentials().expect("Getting username and password failed")
        }
        AuthType::DefaultToken => {
            token_type = Some("default");

            let credentials = cache.credentials().unwrap_or_else(|| {
                ask_user_credentials().expect("Getting username and password failed")
            });

            auth::change_to_token_credentials(credentials).expect("Token retrieval failed")
        }
    };

    let (blob, my_public_key) = match args.auth_type {
        AuthType::Reusable | AuthType::Password | AuthType::DefaultToken => {
            // Generate the blob
            let blob = proto::build_blob(&credentials, &device_info.device_id);

            // Encrypt the blob
            let local_keys = DhLocalKeys::random(&mut rand::thread_rng());
            let encrypted_blob = proto::encrypt_blob(&blob, &local_keys, &device_info.public_key)
                .expect("Encryption of credentials failed");

            (encrypted_blob, base64::encode(local_keys.public_key()))
        }
        AuthType::AccessToken => {
            token_type = Some("accesstoken");

            let client_id = device_info.client_id.expect(
                "To authenticate with an access token, the remote device should provide a clientID",
            );
            let scope = device_info.scope.unwrap_or_else(|| "streaming".into());

            let token = auth::get_token(credentials.clone(), &client_id, &scope)
                .expect("The access token could not be retrieved");

            (token, "".to_string())
        }
    };

    // Send the authentication request
    net::add_user(
        &base_url,
        &credentials.username,
        &blob,
        &my_public_key,
        token_type,
    )
    .expect("Authentication on the remote device failed");

    println!(
        "🎉 Connected as `{}` on `{}` 🎉",
        credentials.username, device_info.remote_name
    );
}
