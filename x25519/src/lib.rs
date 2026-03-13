use wasm_bindgen::prelude::*;
use hkdf::Hkdf;
use sha2::Sha256;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::X25519_BASEPOINT;

// For edwards algorithm
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use sha2::{Sha512, Digest};
use js_sys::{Object, Uint8Array};
use wasm_bindgen::JsValue;

#[wasm_bindgen]
// This function derives a symmetric key from the shared secret using HKDF
pub fn derive_symmetric_key(shared_secret: &[u8]) -> Vec<u8> {
    if shared_secret.len() != 32 {
        return vec![];
    }

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"message-encryption", &mut okm).unwrap();

    okm.to_vec()
}

#[wasm_bindgen]
// This function performs the Diffie-Hellman key exchange using X25519
pub fn diffie_hellman(my_private_key_bytes: &[u8], their_public_key_bytes: &[u8]) -> Vec<u8> {
    if my_private_key_bytes.len() != 32 || their_public_key_bytes.len() != 32 {
        return vec![];
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&my_private_key_bytes[..32]);

    // Clamp private key as per X25519 spec
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;

    // ec scalar for multiplication
    let scalar = Scalar::from_bytes_mod_order(private_key);

    // Converts into ec point and performs scalar multiplication
    let their_public_point = MontgomeryPoint(their_public_key_bytes.try_into().unwrap());
    let shared_point = scalar * their_public_point;

    // Converts to bytes
    shared_point.to_bytes().to_vec()
}

#[wasm_bindgen]
// This function generates a public key from a seed using the ED25519 algorithm
pub fn generate_ed25519_public_key(seed: &[u8]) -> Vec<u8> {
    if seed.len() != 32 {
        return vec![];
    }

    // SHA-512 hash of the seed
    let hash = Sha512::digest(seed);

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);

    // Clamp the scalar
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

    let public_point = &scalar * &ED25519_BASEPOINT_POINT;

    public_point.compress().to_bytes().to_vec()
}

#[wasm_bindgen]
// This function generates a private key from random bytes in EDWARDS form
pub fn generate_ed25519_private_key(js_random_bytes: &[u8]) -> Vec<u8> {
    if js_random_bytes.len() < 32 {
        return vec![];
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&js_random_bytes[..32]);

    seed.to_vec()
}

#[wasm_bindgen]
pub fn derive_x25519_from_ed25519_private(ed25519_seed: &[u8]) -> JsValue {
    if ed25519_seed.len() != 32 {
        return JsValue::NULL;
    }

    // 1. Hash the Ed25519 private seed with SHA-512
    let hash = Sha512::digest(ed25519_seed);

    // 2. Clamp the first 32 bytes to form X25519 private key
    let mut x25519_priv_bytes = [0u8; 32];
    x25519_priv_bytes.copy_from_slice(&hash[..32]);

    x25519_priv_bytes[0] &= 248;
    x25519_priv_bytes[31] &= 127;
    x25519_priv_bytes[31] |= 64;

    // 3. Derive X25519 public key
    let scalar = Scalar::from_bytes_mod_order(x25519_priv_bytes);
    let public_point: MontgomeryPoint = scalar * X25519_BASEPOINT;
    let x25519_pub_bytes = public_point.to_bytes();

    // 4. Return both as JS object
    let result = Object::new();
    js_sys::Reflect::set(&result, &"x25519_private_key".into(), &Uint8Array::from(&x25519_priv_bytes[..])).unwrap();
    js_sys::Reflect::set(&result, &"x25519_public_key".into(), &Uint8Array::from(&x25519_pub_bytes[..])).unwrap();

    result.into()
}


#[wasm_bindgen]
// This function generates a public prekey from a private prekey (Functionally identical to generate_public_key)
pub fn generate_public_prekey(private_prekey_bytes: &[u8]) -> Vec<u8> {
    if private_prekey_bytes.len() != 32 {
        return vec![];
    }

    let mut private_prekey = [0u8; 32];
    private_prekey.copy_from_slice(&private_prekey_bytes[..32]);

    // Clamp manually (as per X25519 spec)
    private_prekey[0] &= 248;
    private_prekey[31] &= 127;
    private_prekey[31] |= 64;

    let scalar = Scalar::from_bytes_mod_order(private_prekey);
    let public_point: MontgomeryPoint = scalar * X25519_BASEPOINT;

    public_point.to_bytes().to_vec()
}

#[wasm_bindgen]
// This function generates a private prekey from random bytes (Functionally identical to generate_private_key)
pub fn generate_private_prekey(js_random_bytes: &[u8]) -> Vec<u8> {
    let mut private_prekey = [0u8; 32];

    if js_random_bytes.len() < 32 {
        return vec![];
    }
    private_prekey.copy_from_slice(&js_random_bytes[..32]);

    private_prekey[0] &= 248;
    private_prekey[31] &= 127;
    private_prekey[31] |= 64;

    private_prekey.to_vec()
}

#[wasm_bindgen]
// This function generates a ephemeral public key
pub fn generate_public_ephemeral_key(private_prekey_bytes: &[u8]) -> Vec<u8> {
    if private_prekey_bytes.len() != 32 {
        return vec![];
    }

    let mut private_prekey = [0u8; 32];
    private_prekey.copy_from_slice(&private_prekey_bytes[..32]);

    // Clamp manually (as per X25519 spec)
    private_prekey[0] &= 248;
    private_prekey[31] &= 127;
    private_prekey[31] |= 64;

    let scalar = Scalar::from_bytes_mod_order(private_prekey);
    let public_point: MontgomeryPoint = scalar * X25519_BASEPOINT;

    public_point.to_bytes().to_vec()
}

#[wasm_bindgen]
// This function generates a private ephemeral key from random bytes
pub fn generate_private_ephemeral_key(js_random_bytes: &[u8]) -> Vec<u8> {
    let mut private_prekey = [0u8; 32];

    if js_random_bytes.len() < 32 {
        return vec![];
    }
    private_prekey.copy_from_slice(&js_random_bytes[..32]);

    private_prekey[0] &= 248;
    private_prekey[31] &= 127;
    private_prekey[31] |= 64;

    private_prekey.to_vec()
}

#[wasm_bindgen]
pub fn hkdf_derive(input_key_material: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);

    let mut okm = vec![0u8; output_len];
    if hkdf.expand(info, &mut okm).is_err() {
        return vec![]; // Handle failure
    }

    okm
}

// The previous HKDF implementation is a combined Extract+Expand. For MLS we need seperate Extract and Expand functions

// HKDF Extract
#[wasm_bindgen]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _hkdf) = Hkdf::<Sha256>::extract(salt_opt, ikm);
    prk.to_vec()
}

// HKDF Expand
#[wasm_bindgen]
pub fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .expect("PRK must be at least HashLen (32) bytes");
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .expect("output_len too large for HKDF-Expand (max 8160 bytes)");
    okm
}



#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // Helper function to avoid JsValue in tests
    fn test_derive_x25519_from_ed25519(ed25519_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if ed25519_seed.len() != 32 {
            return Err("Invalid seed length".to_string());
        }

        let hash = Sha512::digest(ed25519_seed);

        let mut x25519_priv_bytes = [0u8; 32];
        x25519_priv_bytes.copy_from_slice(&hash[..32]);

        x25519_priv_bytes[0] &= 248;
        x25519_priv_bytes[31] &= 127;
        x25519_priv_bytes[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(x25519_priv_bytes);
        let public_point: MontgomeryPoint = scalar * X25519_BASEPOINT;
        let x25519_pub_bytes = public_point.to_bytes();

        Ok((x25519_priv_bytes.to_vec(), x25519_pub_bytes.to_vec()))
    }

    #[test]
    fn test_derive_symmetric_key_valid() {
        let shared_secret = [42u8; 32];
        let derived_key = derive_symmetric_key(&shared_secret);

        assert_eq!(derived_key.len(), 32);
        // Should be deterministic
        let derived_key2 = derive_symmetric_key(&shared_secret);
        assert_eq!(derived_key, derived_key2);
    }

    #[test]
    fn test_derive_symmetric_key_invalid_length() {
        let short_secret = [1u8; 16];
        let result = derive_symmetric_key(&short_secret);
        assert_eq!(result.len(), 0);

        let long_secret = [1u8; 64];
        let result = derive_symmetric_key(&long_secret);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_derive_symmetric_key_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let key1 = derive_symmetric_key(&secret1);
        let key2 = derive_symmetric_key(&secret2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_diffie_hellman_valid() {
        let alice_private = [1u8; 32];
        let bob_private = [2u8; 32];

        let alice_public = generate_public_prekey(&alice_private);
        let bob_public = generate_public_prekey(&bob_private);

        assert_eq!(alice_public.len(), 32);
        assert_eq!(bob_public.len(), 32);

        // Compute shared secrets
        let alice_shared = diffie_hellman(&alice_private, &bob_public);
        let bob_shared = diffie_hellman(&bob_private, &alice_public);

        // Should match
        assert_eq!(alice_shared.len(), 32);
        assert_eq!(bob_shared.len(), 32);
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_diffie_hellman_invalid_private_key_length() {
        let short_private = [1u8; 16];
        let public_key = [2u8; 32];

        let result = diffie_hellman(&short_private, &public_key);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_diffie_hellman_invalid_public_key_length() {
        let private_key = [1u8; 32];
        let short_public = [2u8; 16];

        let result = diffie_hellman(&private_key, &short_public);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_diffie_hellman_deterministic() {
        let private = [5u8; 32];
        let public = [6u8; 32];

        let shared1 = diffie_hellman(&private, &public);
        let shared2 = diffie_hellman(&private, &public);

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_generate_ed25519_public_key_valid() {
        let seed = [7u8; 32];
        let public_key = generate_ed25519_public_key(&seed);

        assert_eq!(public_key.len(), 32);

        // Should be deterministic
        let public_key2 = generate_ed25519_public_key(&seed);
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_generate_ed25519_public_key_invalid_length() {
        let short_seed = [1u8; 16];
        let result = generate_ed25519_public_key(&short_seed);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_generate_ed25519_public_key_different_seeds() {
        let seed1 = [10u8; 32];
        let seed2 = [11u8; 32];

        let pub1 = generate_ed25519_public_key(&seed1);
        let pub2 = generate_ed25519_public_key(&seed2);

        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_generate_ed25519_private_key_valid() {
        let random_bytes = [8u8; 32];
        let private_key = generate_ed25519_private_key(&random_bytes);

        assert_eq!(private_key.len(), 32);
        assert_eq!(private_key, random_bytes.to_vec());
    }

    #[test]
    fn test_generate_ed25519_private_key_invalid_length() {
        let short_bytes = [1u8; 16];
        let result = generate_ed25519_private_key(&short_bytes);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_derive_x25519_from_ed25519_valid() {
        let ed25519_seed = [12u8; 32];
        let result = test_derive_x25519_from_ed25519(&ed25519_seed);

        assert!(result.is_ok());
        let (x25519_priv, x25519_pub) = result.unwrap();

        assert_eq!(x25519_priv.len(), 32);
        assert_eq!(x25519_pub.len(), 32);

        // Should be deterministic
        let result2 = test_derive_x25519_from_ed25519(&ed25519_seed);
        let (x25519_priv2, x25519_pub2) = result2.unwrap();
        assert_eq!(x25519_priv, x25519_priv2);
        assert_eq!(x25519_pub, x25519_pub2);
    }

    #[test]
    fn test_derive_x25519_from_ed25519_invalid_length() {
        let short_seed = [1u8; 16];
        let result = test_derive_x25519_from_ed25519(&short_seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_x25519_different_seeds_produce_different_keys() {
        let seed1 = [13u8; 32];
        let seed2 = [14u8; 32];

        let (priv1, pub1) = test_derive_x25519_from_ed25519(&seed1).unwrap();
        let (priv2, pub2) = test_derive_x25519_from_ed25519(&seed2).unwrap();

        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_generate_public_prekey_valid() {
        let private_key = [15u8; 32];
        let public_key = generate_public_prekey(&private_key);

        assert_eq!(public_key.len(), 32);

        // Should be deterministic
        let public_key2 = generate_public_prekey(&private_key);
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_generate_public_prekey_invalid_length() {
        let short_key = [1u8; 16];
        let result = generate_public_prekey(&short_key);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_generate_private_prekey_valid() {
        let random_bytes = [16u8; 32];
        let private_key = generate_private_prekey(&random_bytes);

        assert_eq!(private_key.len(), 32);

        // Check clamping was applied
        assert_eq!(private_key[0] & 0x07, 0);
        assert_eq!(private_key[31] & 0x80, 0);
        assert_eq!(private_key[31] & 0x40, 0x40);
    }

    #[test]
    fn test_generate_private_prekey_invalid_length() {
        let short_bytes = [1u8; 16];
        let result = generate_private_prekey(&short_bytes);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_generate_public_ephemeral_key_valid() {
        let private_key = [17u8; 32];
        let public_key = generate_public_ephemeral_key(&private_key);

        assert_eq!(public_key.len(), 32);

        // Should be deterministic
        let public_key2 = generate_public_ephemeral_key(&private_key);
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_generate_public_ephemeral_key_invalid_length() {
        let short_key = [1u8; 24];
        let result = generate_public_ephemeral_key(&short_key);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_generate_private_ephemeral_key_valid() {
        let random_bytes = [18u8; 32];
        let private_key = generate_private_ephemeral_key(&random_bytes);

        assert_eq!(private_key.len(), 32);

        // Check clamping was applied
        assert_eq!(private_key[0] & 0x07, 0);
        assert_eq!(private_key[31] & 0x80, 0);
        assert_eq!(private_key[31] & 0x40, 0x40);
    }

    #[test]
    fn test_generate_private_ephemeral_key_invalid_length() {
        let short_bytes = [1u8; 20];
        let result = generate_private_ephemeral_key(&short_bytes);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_hkdf_derive_valid() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";

        let output = hkdf_derive(ikm, salt, info, 32);
        assert_eq!(output.len(), 32);

        // Should be deterministic
        let output2 = hkdf_derive(ikm, salt, info, 32);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_hkdf_derive_different_output_lengths() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let output16 = hkdf_derive(ikm, salt, info, 16);
        let output32 = hkdf_derive(ikm, salt, info, 32);
        let output64 = hkdf_derive(ikm, salt,  info, 64);

        assert_eq!(output16.len(), 16);
        assert_eq!(output32.len(), 32);
        assert_eq!(output64.len(), 64);

        // First 16 bytes of output32 should match output16
        assert_eq!(&output32[..16], &output16[..]);
    }

    #[test]
    fn test_hkdf_derive_different_salt() {
        let ikm = b"input key material";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let info = b"info";

        let output1 = hkdf_derive(ikm, salt1, info, 32);
        let output2 = hkdf_derive(ikm, salt2, info, 32);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_different_info() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info1 = b"context1";
        let info2 = b"context2";

        let output1 = hkdf_derive(ikm, salt, info1, 32);
        let output2 = hkdf_derive(ikm, salt, info2, 32);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_empty_salt() {
        let ikm = b"input key material";
        let salt = b"";
        let info = b"info";

        let output = hkdf_derive(ikm, salt, info, 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_hkdf_derive_empty_info() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"";

        let output = hkdf_derive(ikm, salt, info, 32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_rfc5869_case_1() {
        let ikm = vec![0x0b; 22];
        let salt = hex_to_bytes("000102030405060708090a0b0c");

        let prk = hkdf_extract(&salt, &ikm);
        let expected_prk = hex_to_bytes(concat!(
            "077709362c2e32df0ddc3f0dc47bba63",
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        ));

        assert_eq!(prk, expected_prk);
    }

    #[test]
    fn test_hkdf_expand_rfc5869_case_1() {
        let prk = hex_to_bytes(concat!(
            "077709362c2e32df0ddc3f0dc47bba63",
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        ));
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        let okm = hkdf_expand(&prk, &info, 42);
        let expected_okm = hex_to_bytes(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865"
        ));

        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_extract_expand_matches_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";

        let prk = hkdf_extract(salt, ikm);
        let okm_via_split = hkdf_expand(&prk, info, 48);
        let okm_via_combined = hkdf_derive(ikm, salt, info, 48);

        assert_eq!(okm_via_split, okm_via_combined);
    }

    #[test]
    fn test_hkdf_extract_empty_salt_matches_none_salt_semantics() {
        let ikm = b"ikm-value";
        let prk_from_empty = hkdf_extract(b"", ikm);
        let (expected_prk, _hkdf) = Hkdf::<Sha256>::extract(None, ikm);

        assert_eq!(prk_from_empty, expected_prk.to_vec());
    }

    #[test]
    #[should_panic(expected = "PRK must be at least HashLen (32) bytes")]
    fn test_hkdf_expand_panics_on_short_prk() {
        let short_prk = [0x11u8; 31];
        let _ = hkdf_expand(&short_prk, b"info", 16);
    }

    #[test]
    fn test_full_dh_key_exchange_workflow() {
        // Alice generates keys
        let alice_random = [100u8; 32];
        let alice_private = generate_private_prekey(&alice_random);
        let alice_public = generate_public_prekey(&alice_private);

        // Bob generates keys
        let bob_random = [200u8; 32];
        let bob_private = generate_private_prekey(&bob_random);
        let bob_public = generate_public_prekey(&bob_private);

        // Both perform DH
        let alice_shared = diffie_hellman(&alice_private, &bob_public);
        let bob_shared = diffie_hellman(&bob_private, &alice_public);

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);

        // Derive symmetric keys
        let alice_key = derive_symmetric_key(&alice_shared);
        let bob_key = derive_symmetric_key(&bob_shared);

        assert_eq!(alice_key, bob_key);
        assert_eq!(alice_key.len(), 32);
    }

    #[test]
    fn test_ephemeral_key_generation_workflow() {
        // Generate ephemeral keys
        let random_bytes = [50u8; 32];
        let ephemeral_private = generate_private_ephemeral_key(&random_bytes);
        let ephemeral_public = generate_public_ephemeral_key(&ephemeral_private);

        assert_eq!(ephemeral_private.len(), 32);
        assert_eq!(ephemeral_public.len(), 32);

        // Use in DH exchange
        let static_private = [75u8; 32];
        let static_public = generate_public_prekey(&static_private);

        let shared = diffie_hellman(&ephemeral_private, &static_public);
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn test_ed25519_to_x25519_conversion_workflow() {
        // Generate Ed25519 identity
        let random_bytes = [30u8; 32];
        let ed25519_private = generate_ed25519_private_key(&random_bytes);
        let ed25519_public = generate_ed25519_public_key(&ed25519_private);

        assert_eq!(ed25519_public.len(), 32);

        // Derive X25519 keys from Ed25519 seed
        let (x25519_priv, x25519_pub) = test_derive_x25519_from_ed25519(&ed25519_private).unwrap();

        assert_eq!(x25519_priv.len(), 32);
        assert_eq!(x25519_pub.len(), 32);

        // Use derived X25519 keys in DH
        let peer_private = [40u8; 32];
        let peer_public = generate_public_prekey(&peer_private);

        let shared = diffie_hellman(&x25519_priv, &peer_public);
        assert_eq!(shared.len(), 32);
    }
}
