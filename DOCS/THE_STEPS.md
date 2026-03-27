# Development Steps: geekLock (The Security Sidecar)

This document provides a step-by-step implementation guide suitable for a junior engineer or intern. It breaks down the requirements from `THE_PLAN.md` into actionable development tasks.

## Phase 1: Project Setup

**Goal:** Initialize the Rust environment and configure dependencies.

1. **Install Rust:** Ensure you have the latest stable Rust toolchain installed via `rustup`.
2. **Initialize Project:** 
   - Run `cargo new geeklock` to create a new binary Rust project.
3. **Add Dependencies:** Update `Cargo.toml` with the required crates for cryptography, memory safety, and serialization:
   - `aes-gcm` (for AES-256-GCM authenticated encryption)
   - `rand` (for secure random number generation for DEKs and nonces)
   - `zeroize` (with the `zeroize_derive` feature, for wiping memory)
   - `serde` (with `derive` feature)
   - `bincode` (for binary serialization)
   - `axum` & `tokio` (for the lightweight HTTP API sidecar)

## Phase 2: Core Cryptography Module (`src/crypto.rs`)

**Goal:** Implement the Envelope Encryption logic.

1. **Define Keys and Payloads:**
   - Create a struct for the `DataEncryptionKey` (DEK). Use `#[derive(Zeroize)]` and `#[zeroize(drop)]` so it strictly clears from memory when dropped.
   - Create an `Envelope` struct to hold the `encrypted_data`, `encrypted_dek`, and necessary `nonces`. Derive `Serialize` and `Deserialize`.
2. **Implement DEK Generation:**
   - Write a function to generate a random 32-byte (256-bit) array using `rand::rngs::OsRng`.
3. **Implement Encryption (`encrypt_envelope`):**
   - **Input:** Plaintext (bytes) and the Master Key (KEK).
   - **Process:**
     1. Generate a new DEK.
     2. Encrypt the plaintext using the DEK via `AES-256-GCM`.
     3. Encrypt the DEK itself using the Master Key (KEK).
     4. Let the DEK drop out of scope (Rust + Zeroize handles the memory wipe).
   - **Output:** The `Envelope` struct.
4. **Implement Decryption (`decrypt_envelope`):**
   - **Input:** `Envelope` struct and the Master Key (KEK).
   - **Process:** Decrypt the DEK using the KEK, then decrypt the payload using the DEK.

## Phase 3: Serialization & Memory Safety Verification

**Goal:** Ensure data can be stored in MongoDB and ensure keys do not leak in RAM.

1. **Implement Bincode Integration:**
   - Write unit tests that instantiate an `Envelope`, serialize it to a `Vec<u8>` using `bincode`, and deserialize it back.
2. **Verify Memory Safety:**
   - Add comments and rely on `zeroize(drop)` to ensure your key wrapper structs are actually scrubbed. Ensure no `println!` or logging statements accidentally print plaintext keys.

## Phase 4: API Layer Setup (`src/main.rs`)

**Goal:** Provide an interface for the Node/Express web tier to communicate with geekLock.

1. **Environment Variables:**
   - Read the Master Key (KEK) from the `GEEKLOCK_MASTER_KEY` environment variable on startup. Panic/exit if it's missing (fail securely).
2. **Setup Axum Server:**
   - Create a minimal `tokio` driven HTTP server on a local port (e.g., `127.0.0.1:8080`).
3. **Create Endpoints:**
   - `POST /encrypt`: Accepts JSON `{ "data": "my secret note" }`, calls the crypto module, serializes the `Envelope` via `bincode`, and returns it (potentially Base64 encoded for easy JSON transport back to Node/Mongo).
   - `POST /decrypt`: Accepts the encoded `Envelope`, calls the decrypt module, and returns the plaintext payload.

## Phase 5: Integration Testing

**Goal:** Prove the system works end-to-end.

1. **Write End-to-End Tests:**
   - Send requests to `/encrypt`, verify the output isn't plaintext.
   - Send the output back to `/decrypt` and verify the original data is returned perfectly.
2. **Document the Expected Flow:**
   - Add a brief `README.md` explaining how `baseGeek` (Node) should formulate requests when saving/loading data from MongoDB.
