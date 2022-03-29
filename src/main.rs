use clap::{ArgEnum, Parser};
use librespot_core::{cache::Cache, diffie_hellman::DhLocalKeys};

mod auth;
mod net;
mod proto;

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
    Token,
}

impl Default for AuthType {
    fn default() -> AuthType {
        AuthType::Reusable
    }
}

fn main() {
    // Parse arguments
    let args = Args::parse();
    let base_url = format!("http://{}:{}{}", args.ip, args.port, args.path);

    // Prepare cache
    let mut cache_path = dirs::cache_dir().expect("Impossible to find the user cache directory.");
    cache_path.push("spotify-connect");

    let cache = Cache::new(Some(cache_path), None, None)
        .expect("Impossible to open cache path: {cache_path}");

    // Get credentials
    let credentials = match args.auth_type {
        AuthType::Reusable => {
            cache.credentials().unwrap_or_else(|| {
                // Cache is empty, authenticate to create the credentials
                auth::create_reusable_credentials(cache)
                    .expect("Getting reusable credentials from spotify failed")
            })
        }
        AuthType::Password => {
            auth::ask_user_credentials().expect("Getting username and password failed")
        }
        AuthType::Token => {
            let credentials = cache.credentials().unwrap_or_else(|| {
                auth::ask_user_credentials().expect("Getting username and password failed")
            });

            auth::change_to_token_credentials(credentials).expect("Token retrieval failed")
        }
    };

    // Get device information
    let device_info = net::get_device_info(&base_url)
        .unwrap_or_else(|_| panic!("Impossible to get device information from {base_url}"));
    println!("Found `{}`. Trying to connect...", device_info.remote_name);

    // Generate the blob
    let blob = proto::build_blob(&credentials, &device_info.device_id);

    // Encrypt the blob
    let local_keys = DhLocalKeys::random(&mut rand::thread_rng());
    let encrypted_blob = proto::encrypt_blob(&blob, &local_keys, &device_info.public_key)
        .expect("Encryption of credentials failed");

    // Send the blob
    let my_public_key = base64::encode(local_keys.public_key());
    net::add_user(
        &base_url,
        &credentials.username,
        &encrypted_blob,
        &my_public_key,
    )
    .expect("Authentication on the remote device failed");

    println!(
        "🎉 Connected as `{}` on `{}` 🎉",
        credentials.username, device_info.remote_name
    );
}
