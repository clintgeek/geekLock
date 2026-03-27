use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey([u8; 32]);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub encrypted_data: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
    pub data_nonce: Vec<u8>,
    pub dek_nonce: Vec<u8>,
}

pub fn generate_dek() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt_envelope(plaintext: &[u8], master_key: &[u8; 32]) -> Result<Envelope, String> {
    let dek_raw = generate_dek();
    let dek = SecretKey(dek_raw);
    
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
    
    let encrypted_dek = cipher_dek
        .encrypt(dek_nonce, dek.0.as_slice())
        .map_err(|e| format!("DEK encryption failed: {}", e))?;
        
    // dek.0 is Zeroized on drop due to #[derive(Zeroize)] and #[zeroize(drop)]
    
    Ok(Envelope {
        encrypted_data,
        encrypted_dek,
        data_nonce: data_nonce_bytes.to_vec(),
        dek_nonce: dek_nonce_bytes.to_vec(),
    })
}

pub fn decrypt_envelope(envelope: &Envelope, master_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // Decrypt DEK with Master Key
    let master_kek = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher_dek = Aes256Gcm::new(master_kek);
    let dek_nonce = Nonce::from_slice(&envelope.dek_nonce);
    
    let mut dek_raw = cipher_dek
        .decrypt(dek_nonce, envelope.encrypted_dek.as_slice())
        .map_err(|e| format!("DEK decryption failed: {}", e))?;
    
    if dek_raw.len() != 32 {
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
    }
}
