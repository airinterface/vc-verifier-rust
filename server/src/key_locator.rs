use std::error::Error;
use log::{error, info, warn};
use std::path::Path;

/* #TODO need to implement locating key depends on the implementation */
async fn locate_public_key_from(kid: &str, iss: &str) -> Result<Option<String>, Box<dyn Error>> {
    info!("Looking for the public key with kid: '{}' and iss: '{}'", kid, iss);

    
    /* Picking up from default location Check if the public key exists */
    /* TODO :  */
    let public_key_path = "public_key.pem";
    if !Path::new(public_key_path).exists() {
        error!("Public key not found at {}", public_key_path);
        return Err("Server configuration error: public key not found".into());    
    }

    let public_key = jwt_utils::load_key_from_file(public_key_path).map_err(|e| {
        error!("Failed to load public key: {}", e);
        Box::<dyn Error>::from("Failed to load public key")
    })?;
    Ok(Some(public_key))

}

pub async fn locate_key( jwt: &str ) -> Result<Option<String>, Box<dyn Error>>  {

    /* decode JWT */
    let (header, payload) = jwt_utils::decode_jwt(jwt).map_err(|e| {
        warn!("Failed to decode JWT: {}", e);
        Box::<dyn Error>::from("Failed to decode JWT")
    })?;

    /* Extract `kid` and `iss` from the header and payload */
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'kid' in JWT header")?;
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'iss' in JWT payload")?;
    locate_public_key_from( kid, iss ).await

}