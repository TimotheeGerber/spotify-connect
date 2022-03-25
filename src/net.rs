use serde_json::Value;

#[derive(Debug)]
pub struct DeviceInfo {
    pub device_id: String,
    pub remote_name: String,
    pub public_key: String,
}

/// Get the necessary information from the remote device
pub fn get_device_info(base_url: &str) -> Result<DeviceInfo, Box<dyn std::error::Error>> {
    let response = minreq::get(base_url)
        .with_param("action", "getInfo")
        .send()?;
    let v: Value = serde_json::from_str(response.as_str()?)?;

    let device_id = v["deviceID"]
        .as_str()
        .ok_or("The remote device should provide a `deviceID`")?
        .to_string();
    let remote_name = v["remoteName"]
        .as_str()
        .ok_or("The remote device should provide a `remoteName`")?
        .to_string();
    let public_key = v["publicKey"]
        .as_str()
        .ok_or("The remote device should provide a `publicKey`")?
        .to_string();

    Ok(DeviceInfo {
        device_id,
        remote_name,
        public_key,
    })
}

/// Authenticate on the remote device thanks to the encrypted blob
pub fn add_user(
    base_url: &str,
    username: &str,
    encrypted_blob: &str,
    my_public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = minreq::post(base_url)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_param("action", "addUser")
        .with_param("userName", username)
        .with_param("blob", encrypted_blob)
        .with_param("clientKey", my_public_key)
        .send()?;

    let v: Value = serde_json::from_str(response.as_str()?)?;
    match v["statusString"].as_str() {
        Some("ERROR-OK") => Ok(()),
        Some(err) => Err(err.into()),
        _ => Err(v.to_string().into()),
    }
}
