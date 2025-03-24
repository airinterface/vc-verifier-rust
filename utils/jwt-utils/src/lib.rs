use anyhow::{anyhow, Result};
use josekit::{
    jws::{
        alg::ecdsa::EcdsaJwsAlgorithm,
        JwsHeader,
    },
    jws::ES256, // Use ES256 directly
    jwt::{JwtPayload},
};
use base64::{engine::general_purpose, Engine as _};
use serde_json::{Value};
use std::error::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono;

pub mod models {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct VerifiableCredential {
        #[serde(rename = "@context")]
        pub context: Vec<String>,
        #[serde(rename = "type")]
        pub credential_type: Vec<String>,
        pub issuer: String,
        pub issued_date: String,
        pub credential_subject: CredentialSubject,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jwt: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payload: Option<Value>, 
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct CredentialSubject {
        pub id: String,
        pub name: String,
    }

    /* Structure for nonce request/response */
    #[derive(Serialize, Deserialize, Debug)]
    pub struct NonceResponse {
        pub nonce: String,
    }

    /* Structure for verification response */
    #[derive(Serialize, Deserialize, Debug)]
    pub struct VerificationResponse {
        pub verified: bool,
        pub message: String,
    }
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    /*  Base64url may need padding */
    let mut padded = String::from(input);
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    
    /* Decode base64url to bytes */
    let decoded = general_purpose::URL_SAFE.decode(padded)?;
    Ok(decoded)
}

pub fn decode_jwt(token: &str) -> Result<(Value, Value), Box<dyn Error>> {
    /* Split the token into parts */
    let parts: Vec<&str> = token.split('.').collect();
    
    if parts.len() < 2 {
        return Err("Invalid JWT format".into());
    }
    
    /* Decode the header (first part) */
    let header_json = decode_base64_url(parts[0])?;
    let header: Value = serde_json::from_slice(&header_json)?;
    
    /* Decode the payload (second part) */
    let payload_json = decode_base64_url(parts[1])?;
    let payload: Value = serde_json::from_slice(&payload_json)?;
    println!("Decoded Header: {}", serde_json::to_string_pretty(&header)?); 
    println!("Decoded Payload: {}", serde_json::to_string_pretty(&payload)?); 
    Ok((header, payload))
}

/* Creates a JWT for a Verifiable Credential using ES256 algorithm */
pub fn create_vc_jwt(
    credential: &models::VerifiableCredential,
    private_key_pem: &str,
    key_id: &str,
) -> Result<String> {
    /* Convert credential to JSON for the claim */
    let credential_value = serde_json::to_value(credential)?;
    
    /* Create JWT payload */
    let mut payload = JwtPayload::new();
    
    /* Add standard JWT claims */
    payload.set_claim("iss", Some(Value::String(credential.issuer.clone())))?;
    let issued_timestamp = chrono::DateTime::parse_from_rfc3339(&credential.issued_date)?
        .timestamp();
    payload.set_claim("iat", Some(Value::Number(issued_timestamp.into())))?;
    payload.set_claim("jti", Some(Value::String(Uuid::new_v4().to_string())))?;
    
    /* Add the VC as a nested claim */
    payload.set_claim("vc", Some(credential_value))?;
    
    /* Create header with the key ID */
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(ES256.name()); 
    header.set_key_id(key_id);
    
    /* Create the signer */
    let signer = EcdsaJwsAlgorithm::Es256.signer_from_pem(private_key_pem)?;
    
    /* Sign the JWT */
    let jwt = josekit::jwt::encode_with_signer(&payload, &header, &signer)?;
    
    Ok(jwt)
}

/* Verifies a JWT containing a Verifiable Credential using ES256 algorithm */
pub fn verify_vc_jwt(
    jwt: &str,
    public_key_pem: &str,
) -> Result<models::VerifiableCredential> {
    /* Create the verifier */
    let verifier = EcdsaJwsAlgorithm::Es256.verifier_from_pem(public_key_pem)?;
    
    /* Verify and decode the JWT */
    let (payload, header) = josekit::jwt::decode_with_verifier(jwt, &verifier)?;
    
    /* Verify the algorithm is ES256 */
    if header.algorithm() != Some("ES256") {
        return Err(anyhow!("Invalid algorithm: expected ES256"));
    }
    
    /* Extract the VC claim */
    let vc_value = payload
        .claim("vc")
        .ok_or_else(|| anyhow!("Missing VC claim"))?
        .clone();
    
    /* Deserialize the VC */
    let mut credential: models::VerifiableCredential = serde_json::from_value(vc_value)?;
    
    /* Add the JWT to the credential for reference */
    credential.jwt = Some(jwt.to_string());
    
    Ok(credential)
}

/* Generate a keypair in PEM format for ES256 */
pub fn generate_es256_keypair() -> Result<(String, String)> {
    let key_pair = EcdsaJwsAlgorithm::Es256.generate_key_pair()?; 
    let private_pem = String::from_utf8(key_pair.to_pem_private_key())?;
    let public_pem = String::from_utf8(key_pair.to_pem_public_key())?;
    Ok((private_pem, public_pem))
}

/* Save a key to a file */
pub fn save_key_to_file(key: &str, path: &str) -> Result<()> {
    std::fs::write(path, key)?;
    Ok(())
}

/* Load a key from a file */
pub fn load_key_from_file(path: &str) -> Result<String> {
    let key = std::fs::read_to_string(path)?;
    Ok(key)
}