use std::io::Write;

use clap::{ArgEnum, Parser};
use librespot_core::{authentication::Credentials, cache::Cache};
use librespot_protocol::authentication::AuthenticationType;
use mdns_sd::{ServiceDaemon, ServiceEvent};

use spotify_connect_client as client;

// repeated here to be able to use ArgEnum without creating a library dependency on clap
#[derive(Clone, Debug, Default, ArgEnum)]
pub enum AuthType {
    #[default]
    Reusable,
    Password,
    DefaultToken,
    AccessToken,
}

impl From<AuthType> for client::AuthType {
    fn from(value: AuthType) -> Self {
        match value {
            AuthType::Reusable => client::AuthType::Reusable,
            AuthType::Password => client::AuthType::Password,
            AuthType::DefaultToken => client::AuthType::DefaultToken,
            AuthType::AccessToken => client::AuthType::AccessToken,
        }
    }
}

// included here so that the two types stay in sync
impl From<client::AuthType> for AuthType {
    fn from(value: client::AuthType) -> Self {
        match value {
            client::AuthType::Reusable => AuthType::Reusable,
            client::AuthType::Password => AuthType::Password,
            client::AuthType::DefaultToken => AuthType::DefaultToken,
            client::AuthType::AccessToken => AuthType::AccessToken,
        }
    }
}

/// Use the Spotify Connect feature to authenticate yourself on remote devices
#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    /// Hostname or IP address of the remote device
    host_or_ip: Option<String>,

    /// Port on which the remote device is listening
    port: Option<u16>,

    /// Path to the ZeroConf API on the device web server
    #[clap(default_value = "/")]
    path: String,

    /// The authentication method to use
    #[clap(short, long, arg_enum, default_value_t)]
    auth_type: AuthType,
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

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    // Parse arguments
    let args = Args::parse();

    // Forge the base url of the remote device
    let (host_or_ip, port) = if args.host_or_ip.is_some() && args.port.is_some() {
        // User provided needed information, use it
        (args.host_or_ip.unwrap(), args.port.unwrap())
    } else {
        // Get the device information from mDNS Service Discovery
        let mdns = ServiceDaemon::new().expect("Failed to create daemon");
        let service_type = "_spotify-connect._tcp.local.";
        let receiver = mdns.browse(service_type).expect("Failed to browse");
        let (tx, rx) = std::sync::mpsc::channel();

        println!("Looking for Spotify receivers... (with mdns _sportify-connect._tcp.local. service type)");

        std::thread::spawn(move || {
            let mut spotify_receivers = Vec::new();

            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let ip = match info.get_addresses_v4().into_iter().next() {
                            Some(ip) => ip.clone(),
                            None => continue,
                        };
                        spotify_receivers.push((
                            info.get_hostname().to_string(),
                            ip,
                            info.get_port(),
                        ));
                    }
                    ServiceEvent::SearchStopped(_info) => {
                        break;
                    }
                    _ => {}
                }
            }
            tx.send(spotify_receivers)
                .expect("error while sending the spotify_receivers back");
        });

        std::thread::sleep(std::time::Duration::from_secs(5));
        mdns.stop_browse(service_type)
            .expect("Failed to stop browsing");
        std::thread::sleep(std::time::Duration::from_secs(1));
        mdns.shutdown().unwrap();

        let receivers = rx
            .recv()
            .expect("error while receiving the spotify_receivers");

        dbg!(&receivers);

        (receivers[0].1.to_string(), receivers[0].2)
    };

    // Prepare cache
    let mut cache_path = dirs::cache_dir().expect("Impossible to find the user cache directory.");
    cache_path.push("spotify-connect");

    let cache = Cache::new(Some(cache_path.as_path()), None, None, None).unwrap_or_else(|e| {
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
                client::auth::create_reusable_credentials(cache, credentials).unwrap_or_else(|e| {
                    panic!("Getting reusable credentials from spotify failed: {e}")
                })
            })
        }
        AuthType::Password => ask_user_credentials().expect("Getting username and password failed"),
        AuthType::DefaultToken => {
            let credentials = cache.credentials().unwrap_or_else(|| {
                ask_user_credentials().expect("Getting username and password failed")
            });

            client::auth::change_to_token_credentials(credentials)
                .unwrap_or_else(|e| panic!("Token retrieval failed: {e}"))
        }
    };

    let device_info = client::authenticate(
        &host_or_ip,
        port,
        &args.path,
        &credentials,
        &args.auth_type.into(),
    )
    .unwrap_or_else(|e| panic!("authentication failed: {e}"));

    let more_info = match device_info.active_user.as_deref() {
        Some("") => " (no prior active user)".to_string(),
        Some(username) => format!(" (was {username})"),
        None => "".to_string(),
    };

    println!(
        "🎉 Connected as `{}` on `{}`{} 🎉",
        credentials.username, device_info.remote_name, more_info,
    );
}
