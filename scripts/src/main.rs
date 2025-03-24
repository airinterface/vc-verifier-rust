use anyhow::{Result};
use config::load_env;
use clap::Parser;
use jwt_utils::models::{ NonceResponse, VerifiableCredential};
use reqwest::blocking::Client;
use std::env;
use std::path::Path;
use std::fs::File;


/* Verifire generation command-line arguments */
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /*  Path to the private key PEM file */
    #[arg(long, default_value = "private_key.pem")]
    private_key_pem: String,

    /*  Path to the public key PEM file */
    #[arg(long, default_value = "public_key.pem")]
    public_key_pem: String,

    /*  Path to the Verifiable Credential JSON file */
    #[arg(long, default_value = "credential.json")]
    credential_file: String,
}

/** Generates a key ID based on the issuer and key name */
fn generate_key_id(issuer: &str, key_name: &str) -> String {
    format!("{}#{}", issuer, key_name)
}

/** load json file from file path */
fn from_reader<T>(r: impl std::io::Read) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let reader = std::io::BufReader::new(r);
    let value = serde_json::from_reader(reader)?;
    Ok(value)
}

fn main() -> Result<()> {

    /* Parse command-line arguments */
    let args = Args::parse();
    
    /* Load environment variables */
    load_env();
    
    /*  Get verifier URL from environment variables */
    let verifier_base_url = env::var("VERIFIER_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    
    let nonce_endpoint = format!("{}/nonce", verifier_base_url);
    let verify_endpoint = format!("{}/verify", verifier_base_url);

    

    let mut private_key_path: &str = &args.private_key_pem;
    let mut public_key_path: &str = &args.public_key_pem;

    println!("Using verifier URL: {}", verifier_base_url);
    println!("Using private key path: {}", private_key_path );
    println!("Using public key path: {}", public_key_path);

    let (private_key, _public_key) = if !Path::new(private_key_path).exists() {

        private_key_path = "private_key.pem";
        public_key_path = "public_key.pem";
    
        println!("Generating new ES256 keypair...");
        let (private_pem, public_pem) = jwt_utils::generate_es256_keypair()?;
        
        jwt_utils::save_key_to_file(&private_pem, private_key_path)?;
        jwt_utils::save_key_to_file(&public_pem, public_key_path)?;
        
        (private_pem, public_pem)
    } else {
        println!("Loading existing keypair...");
        let private_pem = jwt_utils::load_key_from_file(private_key_path)?;
        let public_pem = jwt_utils::load_key_from_file(public_key_path)?;
        (private_pem, public_pem)
    };
    
    /* Get a nonce from the verification server */
    let client = Client::new();
    let nonce_response = client.get(&nonce_endpoint)
        .send()?
        .json::<NonceResponse>()?;
    
    println!("Got nonce: {}", nonce_response.nonce);
    
    /* Create the Verifiable Credential */
    let credential_file = File::open(&args.credential_file)
    .map_err(|e| anyhow::anyhow!("Failed to open credential file: {}", e))?;
    let credential: VerifiableCredential = from_reader(credential_file)
        .map_err(|e| anyhow::anyhow!("Failed to parse credential file: {}", e))?;

    /* Generate the key ID */
    let key_id = generate_key_id("did:example:123", "keys-1");
    
    /* Create JWT */
    let jwt = jwt_utils::create_vc_jwt(&credential, &private_key, &key_id)?;
    println!("Created JWT: {}", jwt);
    
    /* Send JWT to verifier */
    let response = client.post(&verify_endpoint)
        .header("Content-Type", "application/jwt")
        .header("X-Nonce", nonce_response.nonce) 
        .body(jwt)
        .send()?;
    
    println!("Verification response status: {}", response.status());
    println!("Verification response body: {}", response.text()?);
    
    Ok(())
}

