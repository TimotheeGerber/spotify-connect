use rand::Rng;
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};

#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    #[serde(rename = "deviceID")]
    pub device_id: String,
    #[serde(rename = "remoteName")]
    pub remote_name: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "tokenType")]
    pub token_type: Option<String>,
    #[serde(rename = "clientID")]
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

/// Get the necessary information from the remote device
pub fn get_device_info(base_url: &str) -> Result<DeviceInfo, Box<dyn std::error::Error>> {
    let response = minreq::get(base_url)
        .with_param("action", "getInfo")
        .send()?;

    let device_info = serde_json::from_str(response.as_str()?)?;

    Ok(device_info)
}

/// Authenticate on the remote device thanks to the encrypted blob
pub fn add_user(
    base_url: &str,
    username: &str,
    blob: &str,
    my_public_key: &str,
    token_type: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let device_id = hex::encode(Sha1::digest("spotify-connect".as_bytes()));
    let login_id = hex::encode(rand::thread_rng().gen::<[u8; 16]>());

    let mut request = minreq::post(base_url)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_param("action", "addUser")
        .with_param("userName", username)
        .with_param("blob", blob)
        .with_param("clientKey", my_public_key)
        .with_param("deviceId", device_id)
        .with_param("deviceName", "spotify-connect")
        .with_param("loginId", login_id);

    if let Some(token_type) = token_type {
        request = request.with_param("tokenType", token_type);
    }

    let response = request.send()?;

    let v: Value = serde_json::from_str(response.as_str()?)?;

    match v["statusString"].as_str() {
        Some("ERROR-OK") | Some("OK") => Ok(()),
        _ => Err(v.to_string().into()),
    }
}
