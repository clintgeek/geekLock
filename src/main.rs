use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tower_http::services::ServeDir;

mod crypto;
use crypto::{encrypt_envelope, decrypt_envelope, Envelope};

struct AppState {
    master_key: [u8; 32],
    encrypt_count: AtomicUsize,
    decrypt_count: AtomicUsize,
    start_time: Instant,
}

#[derive(Deserialize)]
struct EncryptRequest {
    data: String,
}

#[derive(Serialize)]
struct EncryptResponse {
    envelope: String, 
}

#[derive(Deserialize)]
struct DecryptRequest {
    envelope: String, 
}

#[derive(Serialize)]
struct DecryptResponse {
    data: String,
}

#[derive(Serialize)]
struct StatsResponse {
    encryptions: usize,
    decryptions: usize,
    uptime_secs: u64,
    status: String,
}

#[tokio::main]
async fn main() {
    // Load Master Key from environment
    let key_hex = env::var("GEEKLOCK_MASTER_KEY").expect("GEEKLOCK_MASTER_KEY must be set");
    let master_key = decode_hex(&key_hex).expect("Invalid master key hex: must be 64 characters");
    
    let state = Arc::new(AppState { 
        master_key,
        encrypt_count: AtomicUsize::new(0),
        decrypt_count: AtomicUsize::new(0),
        start_time: Instant::now(),
    });

    // Setup routes
    let app = Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .route("/stats", get(stats_handler))
        // Serve UI from src/static
        .fallback_service(ServeDir::new("src/static"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9090));
    println!("geekLock sidecar + Dashboard listening on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn stats_handler(
    State(state): State<Arc<AppState>>,
) -> Json<StatsResponse> {
    Json(StatsResponse {
        encryptions: state.encrypt_count.load(Ordering::Relaxed),
        decryptions: state.decrypt_count.load(Ordering::Relaxed),
        uptime_secs: state.start_time.elapsed().as_secs(),
        status: "Healthy".to_string(),
    })
}

async fn encrypt_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, (StatusCode, String)> {
    state.encrypt_count.fetch_add(1, Ordering::Relaxed);
    
    let envelope = encrypt_envelope(payload.data.as_bytes(), &state.master_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    
    let bin = bincode::serialize(&envelope)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let b64 = STANDARD.encode(bin);
    
    Ok(Json(EncryptResponse { envelope: b64 }))
}

async fn decrypt_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    state.decrypt_count.fetch_add(1, Ordering::Relaxed);
    
    let bin = STANDARD.decode(payload.envelope)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid base64 encoding".to_string()))?;
    
    let envelope: Envelope = bincode::deserialize(&bin)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid envelope format: {}", e)))?;
    
    let plaintext = decrypt_envelope(&envelope, &state.master_key)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    
    let data = String::from_utf8(plaintext)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Decrypted data is not valid UTF-8".to_string()))?;
    
    Ok(Json(DecryptResponse { data }))
}

fn decode_hex(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("Key must be 64 hex characters".to_string());
    }
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
