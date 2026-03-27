# 🛡️ geekLock

> **A FIPS-compliant (logical) cryptographic sidecar built in Rust.**

geekLock acts as the central security boundary for the GeekSuite ecosystem. Designed to isolate cryptographic keys and algorithms away from the primary persistence layer (`baseGeek`), it ensures that sensitive user data, including PII and PHI, is computationally obfuscated using Envelope Encryption.

## Features

- 🔒 **Envelope Encryption:** Uses unique `AES-256-GCM` Data Encryption Keys (DEK) generated randomly for *every* individual record.
- 🧹 **Zeroize Memory Protection:** Implements automatic zeroing of sensitive keys from RAM the moment memory is freed, mitigating "Cold Boot" and memory-scraping attacks.
- 🚀 **Asynchronous High Concurrency:** Powered by `Tokio` and the `Axum` framework, handling thousands of crypto-requests asynchronously without blocking the Node web-tier.
- 📊 **Real-time Diagnostic Dashboard:** A built-in, dark-mode visual interface monitoring throughput via highly performant `AtomicUsize` counters.
- 📦 **Binary Serialization:** High efficiency encoding utilizing `bincode` for payload size reduction before storing in MongoDB.

## Why a Sidecar?

In typical MVC architectures, if an application server is compromised, the attacker gains access to both the database and the encryption keys held in memory.

**geekLock mitigates this by abstracting the key-handling into a separate process:**
If `baseGeek` (the Node tier) is cracked, an attacker can only view encrypted binary blobs. To decrypt any historical data, they need both the database and the Master Key held tightly inside the Rust environment. 

## Documentation

- [Getting Started Guide](GETTING_STARTED.md): Step-by-step instructions on booting the service locally.
- [Integration Guide](INTEGRATION_GUIDE.md): Code examples for connecting Node.js and Python apps to the sidecar.
- [Development Steps](DOCS/THE_STEPS.md): Task breakdown suitable for new engineers to understand the project flow.
- [Implementation Plan](DOCS/THE_PLAN.md): The high-level regulatory compliance mapping behind the sidecar.

## Quick API Overview

geekLock listens on `127.0.0.1:9090` by default.

### `POST /encrypt`
Request:
```json
{ "data": "Sensitive medical data" }
```
Response:
```json
{ "envelope": "JAAAAAAAAAAt8QRLYf..." }
```

### `POST /decrypt`
Request:
```json
{ "envelope": "JAAAAAAAAAAt8QRLYf..." }
```
Response:
```json
{ "data": "Sensitive medical data" }
```

### `GET /` (or `GET /stats` API)
Serves the live diagnostic dashboard monitoring atomic metrics.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
