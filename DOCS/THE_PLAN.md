# Compliance Spec: geekLock (The Security Sidecar)

## 1. Objective

To provide a centralized, FIPS-compliant (logical) cryptographic boundary for the GeekSuite, ensuring that Personally Identifiable Information (PII) and Protected Health Information (PHI) are never stored in plaintext within the persistence layer (baseGeek).

## 2. Regulatory Alignment

- **GDPR (Right to Privacy):** Implements Pseudonymization by decoupling identity from sensitive data via encrypted blobs.
- **HIPAA (Technical Safeguards):** Ensures "Access Control" and "Encryption/Decryption" mechanisms are handled by a dedicated, memory-safe service (Rust).
- **PCI-DSS (Data Protection):** Minimizes the "Audit Scope" by isolating cryptographic keys in the Rust environment, away from the Node/Express web tier.

## 3. Implementation Logic: "The Envelope Pattern"

For a high-security, production-ready architecture, we utilize **Envelope Encryption**:

- **Data Encryption Key (DEK):** The Rust service generates a unique, one-time-use AES key for every single record (e.g., each note in NoteGeek).
- **Key Encryption Key (KEK):** The DEK is then encrypted using a "Master Key" (stored in a secure environment variable or Key Management Service (KMS)).
- **Storage Strategy:** We store the *Encrypted Data* + the *Encrypted DEK* in the persistence layer (MongoDB).

**Rationale:** 
If one record is cracked, the rest of the database remains secure. To decrypt any data, an attacker needs access to both the database *and* the Master Key isolated inside the Rust service.

## 4. Technical Stack (Rust)

- **AEAD (Authenticated Encryption):** `AES-256-GCM`. Provides both Confidentiality (hiding the data) and Authenticity (ensuring the data hasn't been tampered with).
- **Zeroize (`zeroize` crate):** Automatically wipes sensitive keys from RAM as soon as encryption/decryption is finished. This mitigates "Cold Boot" and memory scraping attacks.
- **Serialization (`serde` + `bincode`):** Enables high-performance binary serialization/deserialization of the encrypted payloads.