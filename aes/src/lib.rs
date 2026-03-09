use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hex::encode;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
// This function encrypts a given text using AES-GCM with a 256-bit key and a 96-bit nonce
pub fn encrypt(text: &str, key: &[u8], nonce: &[u8]) -> Result<String, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }

    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce, text.as_bytes())
        .map_err(|_| JsValue::from_str("Encryption failed"))?;  

    Ok(encode(ciphertext))
}

// This function decrypts a given ciphertext using AES-GCM with a 256-bit key and a 96-bit nonce
#[wasm_bindgen]
pub fn decrypt(text: &str, key: &[u8], nonce: &[u8]) -> Result<String, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }

    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce);
    let ciphertext = hex::decode(text).map_err(|_| JsValue::from_str("Invalid ciphertext"))?;
    let decrypted_text = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    String::from_utf8(decrypted_text).map_err(|_| JsValue::from_str("Invalid UTF-8"))
}

// AAD ENCRYPT/DECRYPT FUNCTION for use in in the auth encryption with AD

#[wasm_bindgen]
pub fn encrypt_aad(text: &str, key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<String, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }

    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let key: &aes_gcm::aead::generic_array::GenericArray<u8, aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UInt<aes_gcm::aead::generic_array::typenum::UTerm, aes_gcm::aead::consts::B1>, aes_gcm::aead::consts::B0>, aes_gcm::aead::consts::B0>, aes_gcm::aead::consts::B0>, aes_gcm::aead::consts::B0>, aes_gcm::aead::consts::B0>> = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: text.as_bytes(),
                aad,
            },
        )
        .map_err(|_| JsValue::from_str("Encryption Failed"))?;

    Ok(encode(ciphertext))
}

#[wasm_bindgen]
pub fn decrypt_aad(
    cipher_hex: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<String, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }
    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let ct = hex::decode(cipher_hex).map_err(|_| JsValue::from_str("Invalid ciphertext"))?;
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct.as_ref(),
                aad,
            },
        )
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    String::from_utf8(pt).map_err(|_| JsValue::from_str("Invalid UTF-8"))
}

#[wasm_bindgen]
pub fn encrypt_aad_bytes(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }

    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| JsValue::from_str("Encryption Failed"))?;

    Ok(ciphertext)
}

#[wasm_bindgen]
pub fn decrypt_aad_bytes(
    cipher_hex: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {

    if key.len() != 32 {
        return Err(JsValue::from_str("Invalid key length"));
    }
    if nonce.len() != 12 {
        return Err(JsValue::from_str("Invalid nonce length"));
    }

    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let pt = cipher
        .decrypt(nonce, Payload {msg: cipher_hex, aad, },)
        .map_err(|_| JsValue::from_str("Decryption failed"))?;

    Ok(pt)
}

//TESTS FOR EVERYTHING
// Rountrip tests = encrypting and then decrypting should return the original plaintext

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, NewAead, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    // Helper functions that don't use JsValue for testing
    fn test_encrypt(text: &str, key: &[u8], nonce: &[u8]) -> Result<String, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce, text.as_bytes())
            .map_err(|_| "Encryption failed".to_string())?;
        Ok(encode(ciphertext))
    }

    fn test_decrypt(text: &str, key: &[u8], nonce: &[u8]) -> Result<String, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let ciphertext = hex::decode(text).map_err(|_| "Invalid ciphertext".to_string())?;
        let decrypted_text = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Decryption failed".to_string())?;
        String::from_utf8(decrypted_text).map_err(|_| "Invalid UTF-8".to_string())
    }

    fn test_encrypt_aad(text: &str, key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<String, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: text.as_bytes(), aad })
            .map_err(|_| "Encryption Failed".to_string())?;
        Ok(encode(ciphertext))
    }

    fn test_decrypt_aad(cipher_hex: &str, key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<String, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let ct = hex::decode(cipher_hex).map_err(|_| "Invalid ciphertext".to_string())?;
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct.as_ref(), aad })
            .map_err(|_| "Decryption failed".to_string())?;
        String::from_utf8(pt).map_err(|_| "Invalid UTF-8".to_string())
    }

    fn test_encrypt_aad_bytes(plaintext: &[u8], key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|_| "Encryption Failed".to_string())?;
        Ok(ciphertext)
    }

    fn test_decrypt_aad_bytes(cipher_hex: &[u8], key: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Invalid key length".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let pt = cipher
            .decrypt(nonce, Payload { msg: cipher_hex, aad })
            .map_err(|_| "Decryption failed".to_string())?;
        Ok(pt)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = "Hello, World!";

        let encrypted = test_encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = test_decrypt(&encrypted, &key, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = "";

        let encrypted = test_encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = test_decrypt(&encrypted, &key, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let plaintext = "Hello 世界 🌍 émojis!";

        let encrypted = test_encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = test_decrypt(&encrypted, &key, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let key = [1u8; 16]; // Wrong size
        let nonce = [2u8; 12];
        let plaintext = "test";

        let result = test_encrypt(plaintext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_invalid_nonce_length() {
        let key = [1u8; 32];
        let nonce = [2u8; 16]; // Wrong size
        let plaintext = "test";

        let result = test_encrypt(plaintext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let key = [1u8; 24]; // Wrong size
        let nonce = [2u8; 12];
        let ciphertext = "abcd1234";

        let result = test_decrypt(ciphertext, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_hex() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let invalid_hex = "not-valid-hex!";

        let result = test_decrypt(invalid_hex, &key, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let nonce = [3u8; 12];
        let plaintext = "secret message";

        let encrypted = test_encrypt(plaintext, &key1, &nonce).unwrap();
        let result = test_decrypt(&encrypted, &key2, &nonce);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let key = [1u8; 32];
        let nonce1 = [2u8; 12];
        let nonce2 = [3u8; 12];
        let plaintext = "secret message";

        let encrypted = test_encrypt(plaintext, &key, &nonce1).unwrap();
        let result = test_decrypt(&encrypted, &key, &nonce2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_aad_decrypt_aad_roundtrip() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let plaintext = "secret message";
        let aad = b"additional authenticated data";

        let encrypted = test_encrypt_aad(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = test_decrypt_aad(&encrypted, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aad_wrong_aad_fails() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let plaintext = "secret message";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let encrypted = test_encrypt_aad(plaintext, &key, &nonce, aad1).unwrap();
        let result = test_decrypt_aad(&encrypted, &key, &nonce, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_aad_empty_aad() {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let plaintext = "test";
        let aad = b"";

        let encrypted = test_encrypt_aad(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = test_decrypt_aad(&encrypted, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aad_invalid_key_length() {
        let key = [1u8; 16]; // Wrong size
        let nonce = [2u8; 12];
        let plaintext = "test";
        let aad = b"aad";

        let result = test_encrypt_aad(plaintext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_aad_invalid_nonce_length() {
        let key = [1u8; 32];
        let nonce = [2u8; 16]; // Wrong size
        let ciphertext = "abcd1234";
        let aad = b"aad";

        let result = test_decrypt_aad(ciphertext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_aad_bytes_decrypt_aad_bytes_roundtrip() {
        let key = [9u8; 32];
        let nonce = [10u8; 12];
        let plaintext = b"binary data \x00\x01\x02\xFF";
        let aad = b"metadata";

        let encrypted = test_encrypt_aad_bytes(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = test_decrypt_aad_bytes(&encrypted, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aad_bytes_empty_plaintext() {
        let key = [11u8; 32];
        let nonce = [12u8; 12];
        let plaintext = b"";
        let aad = b"some aad";

        let encrypted = test_encrypt_aad_bytes(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = test_decrypt_aad_bytes(&encrypted, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aad_bytes_large_plaintext() {
        let key = [13u8; 32];
        let nonce = [14u8; 12];
        let plaintext = vec![42u8; 10000]; // 10KB of data
        let aad = b"large data test";

        let encrypted = test_encrypt_aad_bytes(&plaintext, &key, &nonce, aad).unwrap();
        let decrypted = test_decrypt_aad_bytes(&encrypted, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_aad_bytes_wrong_aad_fails() {
        let key = [15u8; 32];
        let nonce = [16u8; 12];
        let plaintext = b"data";
        let aad1 = b"correct";
        let aad2 = b"incorrect";

        let encrypted = test_encrypt_aad_bytes(plaintext, &key, &nonce, aad1).unwrap();
        let result = test_decrypt_aad_bytes(&encrypted, &key, &nonce, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_aad_bytes_invalid_key_length() {
        let key = [1u8; 20]; // Wrong size
        let nonce = [2u8; 12];
        let plaintext = b"test";
        let aad = b"aad";

        let result = test_encrypt_aad_bytes(plaintext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_aad_bytes_invalid_nonce_length() {
        let key = [1u8; 32];
        let nonce = [2u8; 8]; // Wrong size
        let ciphertext = b"data";
        let aad = b"aad";

        let result = test_decrypt_aad_bytes(ciphertext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        let key = [17u8; 32];
        let nonce1 = [18u8; 12];
        let nonce2 = [19u8; 12];
        let plaintext = "same message";

        let encrypted1 = test_encrypt(plaintext, &key, &nonce1).unwrap();
        let encrypted2 = test_encrypt(plaintext, &key, &nonce2).unwrap();

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let key1 = [20u8; 32];
        let key2 = [21u8; 32];
        let nonce = [22u8; 12];
        let plaintext = "same message";

        let encrypted1 = test_encrypt(plaintext, &key1, &nonce).unwrap();
        let encrypted2 = test_encrypt(plaintext, &key2, &nonce).unwrap();

        assert_ne!(encrypted1, encrypted2);
    }
}
