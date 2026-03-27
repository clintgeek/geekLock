use axum::{
    extract::{State, DefaultBodyLimit},
    http::StatusCode,
    response::IntoResponse,
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
use tokio::signal;
use tower_http::{services::ServeDir, trace::TraceLayer};

mod crypto;
use crypto::{encrypt_envelope, decrypt_envelope, Envelope};

struct AppState {
    master_key: [u8; 32],
    encrypt_count: AtomicUsize,
    decrypt_count: AtomicUsize,
    start_time: Instant,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Utility to convert String/Display errors to our standard JSON error response
fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!("Internal crypto error: {}", err);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: err.to_string() }),
    )
}

fn client_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: err.to_string() }),
    )
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
    tracing_subscriber::fmt::init();

    // Load Master Key from environment (fail fast if invalid)
    let key_hex = env::var("GEEKLOCK_MASTER_KEY").expect("GEEKLOCK_MASTER_KEY must be set");
    let master_key = decode_hex(&key_hex).expect("Invalid master key hex: must be 64 characters");
    
    let state = Arc::new(AppState { 
        master_key,
        encrypt_count: AtomicUsize::new(0),
        decrypt_count: AtomicUsize::new(0),
        start_time: Instant::now(),
    });

    // Build our application with routes, fallback UI, limits, trace logging, and state.
    let app = Router::new()
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler))
        .route("/stats", get(stats_handler))
        .fallback_service(ServeDir::new("src/static"))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB explicit hard limit to prevent OOM payloads
        .layer(TraceLayer::new_for_http())              // HTTP access logging
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9090));
    tracing::info!("geekLock sidecar listening on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Graceful shutdown signal received, draining active requests and stopping...");
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
) -> Result<Json<EncryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    
    // Copy variables to move them securely into the spawn_blocking closure
    let master_key = state.master_key;
    let data_bytes = payload.data.into_bytes();
    
    // Perform blocking cryptographic operations off the main Tokio async scheduler
    let envelope = tokio::task::spawn_blocking(move || {
        encrypt_envelope(&data_bytes, &master_key)
    })
    .await
    .map_err(internal_error)? // Catch the JoinError if the thread panicked (rare)
    .map_err(internal_error)?; // Catch the inner crypto error
    
    let bin = bincode::serialize(&envelope).map_err(internal_error)?;
    let b64 = STANDARD.encode(bin);
    
    state.encrypt_count.fetch_add(1, Ordering::Relaxed);
    Ok(Json(EncryptResponse { envelope: b64 }))
}

async fn decrypt_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, Json<ErrorResponse>)> {
    
    let bin = STANDARD.decode(&payload.envelope).map_err(client_error)?;
    let envelope: Envelope = bincode::deserialize(&bin).map_err(client_error)?;
    
    let master_key = state.master_key;
    
    // Perform blocking decryption operations
    let plaintext = tokio::task::spawn_blocking(move || {
        decrypt_envelope(&envelope, &master_key)
    })
    .await
    .map_err(internal_error)?
    .map_err(|e| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e })))?;
    
    let data = String::from_utf8(plaintext).map_err(client_error)?;
    
    state.decrypt_count.fetch_add(1, Ordering::Relaxed);
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
