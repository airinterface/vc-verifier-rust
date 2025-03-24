use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use config::load_env;
use jwt_utils::models::{NonceResponse, VerifiableCredential, VerificationResponse};
use log::{error, info, warn};
use std::env;
use std::sync::{Arc, Mutex};
mod middleware;
use middleware::NonceMiddleware;
use middleware::NonceStore;
mod key_locator;


type AppState = web::Data<Arc<Mutex<NonceStore>>>;

/* Handler: for nonce generation */
async fn get_nonce(state: AppState) -> impl Responder {
    let mut store = state.lock().unwrap();
    let nonce = store.generate_nonce();
    
    info!("Generated new nonce: {}", nonce);
    
    HttpResponse::Ok().json(NonceResponse { nonce })
}



/* Handler for JWT verification */
async fn verify_jwt(_req: HttpRequest, body: String, _state: AppState) -> impl Responder {
    
    /* retrieve  JWT */
    let jwt = body.trim();
    /* locate public key */
    let public_key = match key_locator::locate_key(jwt).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            error!("Failed to locate public key");
            /* validate */
            return HttpResponse::InternalServerError().json(VerificationResponse {
                verified: false,
                message: "Server configuration error: failed to locate public key".to_string(),
            });
        }
        Err(e) => {
            error!("Failed to locate public key: {}", e);
            return HttpResponse::InternalServerError().json(VerificationResponse {
                verified: false,
                message: "Server configuration error: failed to locate public key".to_string(),
            });
        }
    };
    let verification_result: Result<VerifiableCredential> = jwt_utils::verify_vc_jwt(jwt, &public_key);
    
    match verification_result {
        Ok(credential) => {
            // Verify the nonce
            info!("Successfully verified credential for subject: {}", credential.credential_subject.id);
            HttpResponse::Ok().json(VerificationResponse {
                verified: true,
                message: "Credential successfully verified".to_string(),
            })
        },
        Err(e) => {
            warn!("JWT verification failed: {}", e);
            HttpResponse::BadRequest().json(VerificationResponse {
                verified: false,
                message: format!("Verification failed: {}", e),
            })
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    load_env();
    
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    // Create nonce store
    let nonce_store = web::Data::new(Arc::new(Mutex::new(NonceStore::new())));
    
    // Get host and port from environment or use defaults
    let host = env::var("VERIFIER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("VERIFIER_PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("{}:{}", host, port);
    
    info!("Starting verifier server on http://{}", bind_address);
    
    HttpServer::new(move || {
        App::new()
            .app_data(nonce_store.clone())
            .route("/nonce", web::get().to(get_nonce))
            .service(
                web::scope("/verify")
                    .wrap(NonceMiddleware) 
                    .route("", web::post().to(verify_jwt))
            )
    })
    .bind(&bind_address)?
    .run()
    .await
}