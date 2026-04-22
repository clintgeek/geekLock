use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::{Zeroize, Zeroizing};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey([u8; 32]);

/// Current envelope format version. Bump when the on-disk layout changes.
pub const ENVELOPE_VERSION: u8 = 1;
/// Algorithm tag for AES-256-GCM.
pub const ALG_AES_256_GCM: u8 = 1;
/// KEK identifier. Stub for future KEK rotation; always 0 today.
pub const KEK_ID_DEFAULT: u8 = 0;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub version: u8,
    pub kek_id: u8,
    pub alg: u8,
    pub data_nonce: [u8; 12],
    pub dek_nonce: [u8; 12],
    // serde's built-in array impls stop at N=32, so use serde-big-array for the
    // 48-byte DEK ciphertext (32-byte DEK + 16-byte GCM tag).
    #[serde(with = "BigArray")]
    pub encrypted_dek: [u8; 48],
    pub encrypted_data: Vec<u8>,
}

pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

pub fn encrypt_envelope(plaintext: &[u8], master_key: &[u8; 32]) -> Result<Envelope, String> {
    let dek_raw = generate_dek();
    let dek = SecretKey(*dek_raw);

    // Encrypt data with DEK
    let key = Key::<Aes256Gcm>::from_slice(&dek.0);
    let cipher_data = Aes256Gcm::new(key);
    let mut data_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut data_nonce_bytes);
    let data_nonce = Nonce::from_slice(&data_nonce_bytes);

    let encrypted_data = cipher_data
        .encrypt(data_nonce, plaintext)
        .map_err(|e| format!("Data encryption failed: {}", e))?;

    // Encrypt DEK with Master Key (KEK)
    let master_kek = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher_dek = Aes256Gcm::new(master_kek);
    let mut dek_nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut dek_nonce_bytes);
    let dek_nonce = Nonce::from_slice(&dek_nonce_bytes);

    let encrypted_dek_vec = cipher_dek
        .encrypt(dek_nonce, dek.0.as_slice())
        .map_err(|e| format!("DEK encryption failed: {}", e))?;

    // AES-256-GCM over a 32-byte plaintext always yields 32 + 16 = 48 bytes.
    // If it ever doesn't, something deeply weird has happened — fail loudly.
    let encrypted_dek: [u8; 48] = encrypted_dek_vec
        .as_slice()
        .try_into()
        .map_err(|_| format!(
            "DEK ciphertext unexpected length: got {}, want 48",
            encrypted_dek_vec.len()
        ))?;

    // dek.0 is zeroized on drop via SecretKey's Zeroize impl.

    Ok(Envelope {
        version: ENVELOPE_VERSION,
        kek_id: KEK_ID_DEFAULT,
        alg: ALG_AES_256_GCM,
        data_nonce: data_nonce_bytes,
        dek_nonce: dek_nonce_bytes,
        encrypted_dek,
        encrypted_data,
    })
}

pub fn decrypt_envelope(envelope: &Envelope, master_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // Validate envelope metadata BEFORE touching crypto so operators get a
    // clear, actionable error on version / alg / kek mismatch instead of a
    // cryptic AEAD failure.
    if envelope.version != ENVELOPE_VERSION
        || envelope.alg != ALG_AES_256_GCM
        || envelope.kek_id != KEK_ID_DEFAULT
    {
        return Err("unsupported envelope version".to_string());
    }

    // Decrypt DEK with Master Key
    let master_kek = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher_dek = Aes256Gcm::new(master_kek);
    let dek_nonce = Nonce::from_slice(&envelope.dek_nonce);

    let mut dek_raw = cipher_dek
        .decrypt(dek_nonce, envelope.encrypted_dek.as_slice())
        .map_err(|e| format!("DEK decryption failed: {}", e))?;

    if dek_raw.len() != 32 {
        dek_raw.zeroize();
        return Err("Invalid DEK length".to_string());
    }

    let mut dek_array = [0u8; 32];
    dek_array.copy_from_slice(&dek_raw);
    let dek = SecretKey(dek_array);
    dek_raw.zeroize(); // Clean temporary decrypted vector

    // Decrypt data with DEK
    let key = Key::<Aes256Gcm>::from_slice(&dek.0);
    let cipher_data = Aes256Gcm::new(key);
    let data_nonce = Nonce::from_slice(&envelope.data_nonce);

    let plaintext = cipher_data
        .decrypt(data_nonce, envelope.encrypted_data.as_slice())
        .map_err(|e| format!("Data decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_encryption_cycle() {
        let master_key = [7u8; 32];
        let plaintext = b"Hello, GeekSuite!";

        let envelope = encrypt_envelope(plaintext, &master_key).expect("Encryption failed");
        assert_eq!(envelope.version, ENVELOPE_VERSION);
        assert_eq!(envelope.alg, ALG_AES_256_GCM);
        assert_eq!(envelope.kek_id, KEK_ID_DEFAULT);
        assert_ne!(envelope.encrypted_data, plaintext);

        let decrypted = decrypt_envelope(&envelope, &master_key).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_master_key_fails() {
        let master_key = [7u8; 32];
        let wrong_key = [8u8; 32];
        let plaintext = b"Super Secret";

        let envelope = encrypt_envelope(plaintext, &master_key).expect("Encryption failed");
        let result = decrypt_envelope(&envelope, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_serialization() {
        let master_key = [1u8; 32];
        let plaintext = b"Serialize me!";
        let envelope = encrypt_envelope(plaintext, &master_key).unwrap();

        let serialized = bincode::serialize(&envelope).expect("Serialization failed");
        let deserialized: Envelope = bincode::deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(envelope.encrypted_data, deserialized.encrypted_data);
        assert_eq!(envelope.encrypted_dek, deserialized.encrypted_dek);
        assert_eq!(envelope.data_nonce, deserialized.data_nonce);
        assert_eq!(envelope.dek_nonce, deserialized.dek_nonce);
        assert_eq!(envelope.version, deserialized.version);
    }

    #[test]
    fn test_unsupported_version_rejected_before_crypto() {
        let master_key = [7u8; 32];
        let plaintext = b"future me";

        let mut envelope = encrypt_envelope(plaintext, &master_key).unwrap();
        envelope.version = 2;

        let err = decrypt_envelope(&envelope, &master_key).expect_err("should reject v2");
        assert_eq!(err, "unsupported envelope version");
    }

    #[test]
    fn test_unsupported_alg_rejected_before_crypto() {
        let master_key = [7u8; 32];
        let envelope = Envelope {
            version: 1,
            kek_id: 0,
            alg: 99,
            data_nonce: [0u8; 12],
            dek_nonce: [0u8; 12],
            encrypted_dek: [0u8; 48],
            encrypted_data: vec![],
        };
        let err = decrypt_envelope(&envelope, &master_key).expect_err("should reject alg=99");
        assert_eq!(err, "unsupported envelope version");
    }

    #[test]
    fn test_corrupted_envelope_rejected_at_deserialize() {
        let master_key = [3u8; 32];
        let plaintext = b"tamper with me";
        let envelope = encrypt_envelope(plaintext, &master_key).unwrap();

        // Serialize, then corrupt the very first byte (the version field).
        // This should still deserialize (u8 accepts any value) but fail the
        // version check in decrypt_envelope.
        let mut blob = bincode::serialize(&envelope).unwrap();
        blob[0] = 0xFF;
        let bad: Envelope = bincode::deserialize(&blob).expect("u8 version always deserializes");
        let err = decrypt_envelope(&bad, &master_key).expect_err("should reject corrupted version");
        assert_eq!(err, "unsupported envelope version");

        // Now truncate the blob to something too short for the fixed-size
        // arrays — bincode should reject this at deserialize time.
        let truncated = &blob[..5];
        let result: Result<Envelope, _> = bincode::deserialize(truncated);
        assert!(result.is_err(), "truncated envelope must fail to deserialize");
    }
}
