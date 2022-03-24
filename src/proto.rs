use aes_ctr::cipher::generic_array::GenericArray;
use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use hmac::{Hmac, Mac};
use librespot_core::{authentication::Credentials, diffie_hellman::DhLocalKeys};
use sha1::{Digest, Sha1};

/// Create an encrypted blob with authentication data
///
/// This has been written by reversing the instructions in the `with_blob`
/// method of `librespot_core::authentication::Credentials` structure.
pub fn build_blob(credentials: &Credentials, device_id: &str) -> String {
    let mut blob: Vec<u8> = vec![0x49]; // 'I'
                                        // username
    blob.push(credentials.username.len() as u8);
    blob.extend(credentials.username.as_bytes());
    // 'P'
    blob.push(0x50);
    // auth_type STORED_SPOTIFY_CREDENTIALS
    blob.push(0x01);
    // 'Q'
    blob.push(0x51);
    // auth_data 135-bytes token
    blob.push(0x87);
    blob.push(0x01);
    blob.extend(&credentials.auth_data);
    // Padding
    let n_zeros = 16 - (blob.len() % 16) - 1;
    blob.extend(vec![0; n_zeros]);
    blob.push(n_zeros as u8 + 1);

    let l = blob.len();
    for i in (0..l - 0x10).rev() {
        blob[l - i - 1] ^= blob[l - i - 0x11];
    }

    let secret = Sha1::digest(device_id.as_bytes());

    let key = {
        let mut key = [0u8; 24];
        pbkdf2::pbkdf2::<Hmac<Sha1>>(
            &secret,
            credentials.username.as_bytes(),
            0x100,
            &mut key[0..20],
        );

        let hash = Sha1::digest(&key[..20]);
        key[..20].copy_from_slice(&hash);
        key[23] = 20u8;
        key
    };

    let encrypted_blob = {
        use aes::cipher::generic_array::typenum::Unsigned;
        use aes::cipher::{BlockCipher, NewBlockCipher};

        let mut data = blob;
        let cipher = aes::Aes192::new(GenericArray::from_slice(&key));
        let block_size = <aes::Aes192 as BlockCipher>::BlockSize::to_usize();

        assert_eq!(data.len() % block_size, 0);
        for chunk in data.chunks_exact_mut(block_size) {
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        }

        data
    };

    base64::encode(encrypted_blob)
}

/// Encrypt the blob with Diffie-Hellman keys
///
/// This has been written by reversing the instructions in the `handle_add_user`
/// method of `librespot_core::discovery::server::RequestHandler` structure.
pub fn encrypt_blob(
    blob: &str,
    local_keys: &DhLocalKeys,
    remote_device_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let remote_device_key = base64::decode(remote_device_key)?;
    let shared_key = local_keys.shared_secret(&remote_device_key);

    let base_key = Sha1::digest(&shared_key);
    let base_key = &base_key[..16];

    let checksum_key = {
        let mut h = Hmac::<Sha1>::new_from_slice(base_key).expect("HMAC can take key of any size");
        h.update(b"checksum");
        h.finalize().into_bytes()
    };

    let encryption_key = {
        let mut h = Hmac::<Sha1>::new_from_slice(base_key).expect("HMAC can take key of any size");
        h.update(b"encryption");
        h.finalize().into_bytes()
    };

    let iv: [u8; 16] = [
        253, 81, 222, 19, 70, 203, 45, 89, 141, 68, 210, 240, 93, 20, 76, 30,
    ];

    let encrypted_blob = {
        let mut data = blob.bytes().collect::<Vec<u8>>();
        let mut cipher = Aes128Ctr::new(
            GenericArray::from_slice(&encryption_key[0..16]),
            GenericArray::from_slice(&iv),
        );
        cipher.apply_keystream(&mut data);
        data
    };

    let checksum = {
        let mut h =
            Hmac::<Sha1>::new_from_slice(&checksum_key).expect("HMAC can take key of any size");
        h.update(&encrypted_blob);
        h.finalize().into_bytes()
    };

    let mut encrypted_signed_blob: Vec<u8> = Vec::new();
    encrypted_signed_blob.extend(&iv);
    encrypted_signed_blob.extend(&encrypted_blob);
    encrypted_signed_blob.extend(&checksum);

    Ok(base64::encode(encrypted_signed_blob))
}

// -----
// Tests
// -----
#[cfg(test)]
mod tests {
    use super::*;

    use librespot_protocol::authentication::AuthenticationType;
    use rand::SeedableRng;

    // User
    const USERNAME: &'static str = "my_username";
    const AUTH_DATA: &'static str = "A_135-bytes_long_string::123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~===============================";

    // Remote device
    const DEVICE_ID: &'static str = "ce8d71004f9597141d4b5940bd1bb2dc52a35dae";
    const DEVICE_KEY: &'static str = "U6+5+tIcqTzlX8Z6CA+DDGXgiIB270+D4l1gu4EUyKMS1g4j2JpdLu8xNWkw9uyKcvSvn/nKBCusEzaRIDJXau9GMCR+QdN9Iu2MM0/ME5flWUvOnq+O16mkK2IvD9GY";

    // Expected results
    const BLOB: &'static str = "w76y80SFmb3PIAUvjHsSoMvLEeVrYQ6Xa+g1QBwCSIHwH5pH6KzOvPY1qK/HBnqLcKYuasYsBsvvD/bhYGViZmgF+yiR5glUoaRGqVWDvxMuyTPLuoJpPjFBfOt0MqWQEbzchqvws7au6oO9Y7X1hNhLikDs3dz4w/ZhKen1ElKnDSJuylMwWMibLNiT6Yaiqr/rPpBUChNkObtU87mL+A==";
    const ENCRYPTED_BLOB: &'static str = "/VHeE0bLLVmNRNLwXRRMHiGvoLe0y9EFU7t0yfMp10W/m36RmsbShZyrMUG+GI9LA4K8epc30Wj9rjTn2INrR+a4C+nvTECaZsbPcdgUL0MJTkWzqFjo326Ev9FKZEhy1i47A9Y94ZRF2erPRSuDuw1QVqacDt/XrFGPWDdb3cI6GINSirtPTdifPcSI7e722eR8Z5XsbaiCOeLbBaFwB8jiHh08wRAKFruwRoT7pO3koXcLHQqbiXtx/vtim+1tvw9J5tuh42jJnf8qyiVtOVeFmT39trU6sDA22ZONZMjPQ73qC30goFbVUIG4wphHxeF8UX2VpKcTxMAn";

    #[test]
    fn blob_creation() {
        let credentials = Credentials {
            username: USERNAME.to_string(),
            auth_type: AuthenticationType::AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS,
            auth_data: AUTH_DATA.as_bytes().into(),
        };

        assert_eq!(build_blob(&credentials, DEVICE_ID), BLOB);
    }

    #[test]
    fn blob_encryption() {
        let local_keys = DhLocalKeys::random(&mut rand::rngs::StdRng::seed_from_u64(0x42));

        assert_eq!(
            encrypt_blob(BLOB, &local_keys, DEVICE_KEY).unwrap(),
            ENCRYPTED_BLOB
        );
    }
}
