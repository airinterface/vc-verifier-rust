use actix_web::{web, HttpResponse, error::InternalError, Error};
use actix_web::dev::{ Transform, Service, ServiceRequest, ServiceResponse };
use std::collections::HashSet;
use futures_util::future::{LocalBoxFuture};
use std::rc::Rc;
use uuid::Uuid;
use std::{future::{ready, Ready}};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use log::{warn};
use serde::{Deserialize, Serialize};

/* Nonce storage with expiration */
pub struct NonceStore {
    nonces: HashSet<String>,
    used_nonces: HashSet<String>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            nonces: HashSet::new(),
            used_nonces: HashSet::new(),
        }
    }
    
    pub fn generate_nonce(&mut self) -> String {
        let nonce = Uuid::new_v4().to_string();
        self.nonces.insert(nonce.clone());
        nonce
    }
    
    pub fn verify_and_invalidate_nonce(&mut self, nonce: &str) -> bool {
        if self.nonces.contains(nonce) && !self.used_nonces.contains(nonce) {
            self.nonces.remove(nonce);
            self.used_nonces.insert(nonce.to_string());
            true
        } else {
            false
        }
    }
}



/* Middleware to log and validate the `X-Nonce` header */
pub struct NonceMiddleware;

impl<S, B> Transform<S, ServiceRequest> for NonceMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = NonceMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(NonceMiddlewareService { service: Rc::new(service) }))
    }
}

pub struct NonceMiddlewareService<S> {
    service: Rc<S>,
}

pub struct NonceVerifyResponse {
    result: bool, 
    message: String,
}


#[derive(Serialize, Deserialize, Debug)]
struct NonceMiddlewareResponse {
    pub verified: bool,
    pub message: String,
}


fn generate_error(message: String) -> Error {
    let error_message = message.clone();
    let error_response = HttpResponse::BadRequest()
    .content_type("application/json")
    .json(serde_json::json!({
        "error": message
    }));

    InternalError::from_response(
        error_message,
        error_response
    ).into()

}

fn verify_nounce(req: &ServiceRequest) ->  NonceVerifyResponse {
    let state = req
    .app_data::<web::Data<Arc<Mutex<NonceStore>>>>()
    .expect("NonceStore is not configured");

    /* Obtain Nonce from the header */
    let nonce = match req.headers().get("X-Nonce") {
        Some(value) => match value.to_str() {
            Ok(nonce) => nonce.to_string(),
            Err(_) => {
                return NonceVerifyResponse {
                    result: false,
                    message: "Invalid nonce format in header".to_string(),
                }
            }
        },
        None => {
            warn!("Missing nonce in header");
            return NonceVerifyResponse {
                result: false,
                message: "Missing nonce in header".to_string(),
            }
    }
    };



    /*  Validate the nonce */
    let valid_nonce = {
        let mut store = state.lock().unwrap();
        store.verify_and_invalidate_nonce(&nonce)
    };

    NonceVerifyResponse{    
        result: valid_nonce,
        message: if valid_nonce { "".to_string() } else { "Invalid or already used nonce".to_string() },
    }
}


impl<S, B> actix_service::Service<ServiceRequest> for NonceMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static, 
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), actix_web::Error>> {
        self.service.poll_ready(cx)
    }
    
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let nounce_res = verify_nounce( &req );
        if !nounce_res.result {

            return Box::pin(async move{
                Err(generate_error(nounce_res.message))
            });
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

