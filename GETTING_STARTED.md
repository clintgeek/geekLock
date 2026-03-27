# Getting Started: geekLock Sidecar

This guide explains how to run the geekLock security sidecar locally for development, testing, or integration into the GeekSuite ecosystem.

## Prerequisites

1.  **Rust Toolchain:** You must have Rust installed (`v1.75+` recommended).
    - Install via [`rustup`](https://rustup.rs/): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
    - Verify with: `cargo --version`

## Step 1: Clone and Build

Navigate to the project directory and build the application.

```bash
cd geekLock
cargo build
```

*Note: The first build will take a moment as it downloads dependencies like `axum`, `tokio`, and `aes-gcm`.*

## Step 2: Configure Environment

geekLock requires a 256-bit (32 byte) Master Key to encrypt and decrypt the Data Encryption Keys (DEKs). This is passed as a hexadecimal string.

For local development, you can use a placeholder key, but in production, this should be injected securely via a KMS or vaulted secret.

```bash
export GEEKLOCK_MASTER_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

## Step 3: Run the Sidecar

Start the server using Cargo:

```bash
cargo run
```

If successful, you will see:
```
geekLock sidecar + Dashboard listening on http://127.0.0.1:9090
```

## Step 4: Verify the Dashboard

geekLock comes with a built-in Diagnostic Dashboard for tracking real-time operations and cryptographic boundary health.

1. Open your browser.
2. Navigate to `http://127.0.0.1:9090/`.
3. You should see a Dark Mode UI indicating "System Healthy" alongside real-time atomic counters for encryptions, decryptions, and uptime.

## Step 5: Test the API Endpoints

You can verify the core cryptography is functioning using `curl` from another terminal window.

**1. Encrypt Data**
```bash
curl -X POST http://127.0.0.1:9090/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "My sensitive PII/PHI dataset"}'
```
*You will receive a Base64-encoded `envelope` string back. Copy that string for the next step.*

**2. Decrypt Data**
Extract the `envelope` from your previous response and insert it below:
```bash
curl -X POST http://127.0.0.1:9090/decrypt \
  -H "Content-Type: application/json" \
  -d '{"envelope": "INSERT_BASE64_ENVELOPE_HERE"}'
```
*You should receive your original sensitive string back.*

## Next Steps for Integrators

If you are integrating `geekLock` into a Node.js API (e.g., `baseGeek`), structure your HTTP requests to point to the sidecar before saving to MongoDB, and point to the sidecar after retrieving from MongoDB. The web layer should **never** log or persist the raw plaintext.
