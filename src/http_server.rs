use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use crate::eip712::{verify_eip712_signature, Eip712Domain};
use crate::intent_contract::calculate_intent_id;
use crate::intent_system::{CoreLaneIntentSystem, IntentSystem, LockData};
use crate::intent_types::IntentData;
use alloy_primitives::{Address, Bytes};
use ciborium::from_reader;
use std::io::Cursor;
use std::str::FromStr;

/// Request payload from the exit-intent-signer
#[derive(Debug, Deserialize)]
pub struct IntentSubmissionRequest {
    pub eip712sig: String,
    pub lock_data: String,
    pub typed_data: TypedData,
    pub intent_hex: String,
    pub from: String,
    pub chain_id: u64,
    pub verifying_contract: String,
}

/// Typed data structure from the request
#[derive(Debug, Deserialize)]
pub struct TypedData {
    pub domain: serde_json::Value,
    pub types: serde_json::Value,
    pub message: CreateIntentMessage,
}

/// EIP-712 message structure
#[derive(Debug, Deserialize)]
pub struct CreateIntentMessage {
    pub intent: String,
    pub nonce: String,
    pub value: String,
}

/// Response payload
#[derive(Debug, Serialize)]
pub struct IntentSubmissionResponse {
    pub success: bool,
    pub intent_id: Option<String>,
    pub message: String,
}

type HttpError = (StatusCode, Json<IntentSubmissionResponse>);

fn bad_request(message: impl Into<String>) -> HttpError {
    (
        StatusCode::BAD_REQUEST,
        Json(IntentSubmissionResponse {
            success: false,
            intent_id: None,
            message: message.into(),
        }),
    )
}

fn internal_error(message: impl Into<String>) -> HttpError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(IntentSubmissionResponse {
            success: false,
            intent_id: None,
            message: message.into(),
        }),
    )
}

fn decode_hex_field(value: &str) -> Result<Vec<u8>, HttpError> {
    let trimmed = value.trim_start_matches("0x");
    hex::decode(trimmed).map_err(|e| bad_request(format!("Invalid hex: {}", e)))
}

fn parse_cbor_field<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, HttpError> {
    from_reader(Cursor::new(bytes)).map_err(|e| {
        error!("Failed to parse CBOR: {}", e);
        bad_request(format!("Invalid CBOR: {}", e))
    })
}

/// HTTP server state
pub struct HttpServerState {
    pub intent_system: Arc<CoreLaneIntentSystem>,
}

/// Create HTTP server router
pub fn create_router(state: HttpServerState) -> Router {
    // Configure CORS to allow requests from browser
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    // Add request logging
    let trace_layer = TraceLayer::new_for_http().on_request(
        |_request: &axum::http::Request<_>, _span: &tracing::Span| {
            info!(
                "📨 Incoming HTTP request: {} {}",
                _request.method(),
                _request.uri()
            );
        },
    );

    Router::new()
        .route("/intents", post(submit_intent))
        .route("/health", get(health_check))
        .layer(cors)
        .layer(trace_layer)
        .with_state(Arc::new(state))
}

async fn health_check() -> impl IntoResponse {
    info!("Health check requested");
    Json(serde_json::json!({
        "status": "ok",
        "service": "filler-bot"
    }))
}

async fn submit_intent(
    State(state): State<Arc<HttpServerState>>,
    Json(payload): Json<IntentSubmissionRequest>,
) -> impl IntoResponse {
    info!(
        "📥 Received intent submission request from {}",
        payload.from
    );

    let eip712sig = match decode_hex_field(&payload.eip712sig) {
        Ok(sig) => {
            if sig.len() != 65 {
                return bad_request(format!(
                    "Invalid signature length: expected 65 bytes, got {}",
                    sig.len()
                ))
                .into_response();
            }
            sig
        }
        Err(err) => return err.into_response(),
    };

    let lock_data_bytes = match decode_hex_field(&payload.lock_data) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };
    let intent_bytes = match decode_hex_field(&payload.intent_hex) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };

    let lock_data: LockData = match parse_cbor_field(&lock_data_bytes) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };
    let intent_data: IntentData = match parse_cbor_field(&intent_bytes) {
        Ok(d) => d,
        Err(err) => return err.into_response(),
    };

    let nonce = lock_data.nonce;
    let value = lock_data.value;

    let domain = Eip712Domain::from(&payload.typed_data.domain);
    let signer_address =
        match verify_eip712_signature(&domain, &intent_bytes, nonce, value, &eip712sig) {
            Ok(addr) => addr,
            Err(e) => {
                error!("EIP-712 signature verification failed: {}", e);
                return bad_request(format!("Invalid signature: {}", e)).into_response();
            }
        };

    let from_address = match Address::from_str(&payload.from) {
        Ok(addr) => addr,
        Err(e) => return bad_request(format!("Invalid from address: {}", e)).into_response(),
    };

    info!(
        "EIP-712 signature verified. Signer: {}, From: {}, Intent type: {:?}",
        signer_address, from_address, intent_data.intent_type
    );

    let nonce_u64 = nonce.to::<u64>();
    let intent_id =
        calculate_intent_id(signer_address, nonce_u64, Bytes::from(intent_bytes.clone()));

    if let Err(e) = state
        .intent_system
        .create_intent_and_lock(&eip712sig, &lock_data_bytes, signer_address)
        .await
    {
        error!("Failed to create intent: {}", e);
        return internal_error(format!("Failed to create intent: {}", e)).into_response();
    }

    info!("Successfully created intent with ID: 0x{:x}", intent_id);

    Json(IntentSubmissionResponse {
        success: true,
        intent_id: Some(format!("0x{:x}", intent_id)),
        message: "Intent created successfully".to_string(),
    })
    .into_response()
}
