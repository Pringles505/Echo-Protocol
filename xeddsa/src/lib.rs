use wasm_bindgen::prelude::*;
use sha2::{Sha512, Digest};
use num_bigint::BigUint;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use web_sys::console;

// For logging
macro_rules! log_bytes {
    ($label:expr, $bytes:expr) => {
        console::log_1(&format!("{}: {:?}", $label, &$bytes[..]).into());
    };
}

// This struct is used to hold the decoded signature components
pub struct DecodedXedSignature {
    pub r: EdwardsPoint,
    pub s: Scalar,
    pub r_bytes: [u8; 32],
}

// This function decodes a signature from a byte array 
pub fn decode_xeddsa_signature(signature: &[u8]) -> Result<DecodedXedSignature, &'static str> {
    // Check if signature length is 64 bytes
    if signature.len() != 64 {
        return Err("Signature must be 64 bytes (R || S)");
    }

    let mut s_bytes = [0u8; 32];
    let mut r_bytes = [0u8; 32];

    // Extract R and S from the signature
    s_bytes.copy_from_slice(&signature[32..64]);
    r_bytes.copy_from_slice(&signature[0..32]);

    // Decode R point (Nonce point R)
    let compressed_r = CompressedEdwardsY(r_bytes);
    let r_point = compressed_r
        .decompress()
        .ok_or("Failed to decompress R point")?;

    let s_ctopt = Scalar::from_canonical_bytes(s_bytes);
    if s_ctopt.is_some().unwrap_u8() == 0 {
        return Err("Invalid scalar S (not canonical)");
    }
    let s_scalar = s_ctopt.unwrap();

    // Decoded R, S from Signature
    Ok(DecodedXedSignature {
        r: r_point,
        s: s_scalar,
        r_bytes,
    })
}

// This function reduces the hash to a scalar mod L (% L)
pub fn reduce_hash_mod_l(hash: &[u8]) -> BigUint {
    let big = BigUint::from_bytes_le(hash);
    big % ed25519_l()
}

// To get the order of the curve L
pub fn ed25519_l() -> BigUint {
    BigUint::parse_bytes(
        b"7237005577332262213973186563042994240857116359379907606001950938285454252873",
        10,
    ).unwrap()
}

// This function computes the SHA-512 hash of the input data and returns a 64-byte array
pub fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize(); 
    let mut out = [0u8; 64];
    out.copy_from_slice(&result); 
    out
}

// This function converts a BigUint to a 32-byte array
fn biguint_to_scalar_bytes(value: &BigUint) -> [u8; 32] {
    let mut bytes = value.to_bytes_le(); 
    bytes.resize(32, 0); 

    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&bytes);
    fixed
}

// Clamp the byte array acording to X25519 rules
pub fn clamp(private_key: &mut [u8; 32]) {
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
}

#[wasm_bindgen]
/// This function converts a X25519 private key to an XEdDSA private key
pub fn convert_x25519_to_xeddsa(private_key_bytes: &[u8]) -> Vec<u8> {
    //Sha512 the private key
    let h = sha512_bytes(private_key_bytes);

    //Seperate the first 32 bytes and the last 32 bytes
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];

    a.copy_from_slice(&h[0..32]);
    prefix.copy_from_slice(&h[32..64]);

    // Clamp the private key
    clamp(&mut a);

    //Concatenate and return 
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&a);
    result.extend_from_slice(&prefix);
    
    result

}   

#[wasm_bindgen]
// Compute r, r = SHA(Prefix + message) % L
//// where Prefix is the prefix from the XEdDSA key and message is the message to sign
pub fn compute_determenistic_nonce(prefix: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(message);
    let hash_result = hasher.finalize();
    
    let big = BigUint::from_bytes_le(&hash_result);
    let l = ed25519_l();
    let reduced = big % l;

    let mut bytes = reduced.to_bytes_le();
    bytes.resize(32, 0); 

    bytes
}   

#[wasm_bindgen]
// Compute R, R = B * r
// where B is the base point and r is the nonce
pub fn compute_nonce_point(nonce_bytes: &[u8]) -> Vec<u8> {
    // Check length
    if nonce_bytes.len() != 32 {
        panic!("nonce_bytes must be exactly 32 bytes");
    }

    // Convert &[u8] to [u8; 32]
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes.copy_from_slice(&nonce_bytes[0..32]);

    // Create scalar and compute R = r * B
    let scalar = Scalar::from_bytes_mod_order(fixed_bytes);
    let point = &scalar * &ED25519_BASEPOINT_POINT;

    // Compress and return as Vec<u8>
    point.compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn derive_ed25519_keypair_from_x25519(private_key_bytes: &[u8]) -> Vec<u8> {
    let h = sha512_bytes(private_key_bytes);

    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);

    //Important: Clamp the private key
    clamp(&mut a);

    let scalar = Scalar::from_bytes_mod_order(a);
    let point = &scalar * &ED25519_BASEPOINT_POINT;

    point.compress().to_bytes().to_vec()
}

#[wasm_bindgen]
// Compute k, k = SHA(R || publicEdKey || message) % L
// where R is the nonce point, publicEdKey is the public key, and message is the message to sign
pub fn compute_challenge_hash(nonce_point: &[u8], public_ed_key: &[u8], message: &[u8]) -> Vec<u8> {
    // Check lengths
    if nonce_point.len() != 32 || public_ed_key.len() != 32 {
        panic!("edPrivScaler and publicEdKey must be exactly 32 bytes");
    }

    let mut hasher = Sha512::new();
    hasher.update(nonce_point);
    hasher.update(public_ed_key);
    hasher.update(message);


    let hash_result = hasher.finalize();
    let reduced_scalar = reduce_hash_mod_l(&hash_result);
    
    let mut bytes = reduced_scalar.to_bytes_le();
    bytes.resize(32, 0); 
    bytes
}

#[wasm_bindgen]
// Compute s, s = r + k * a
// where r is the nonce, k is the challenge hash, and a is the private key scalar
pub fn compute_signature_scaler(nonce: &[u8], challenge_hash: &[u8], ed_private_scalar: &[u8]) -> Vec<u8> {
    if nonce.len() != 32 || challenge_hash.len() != 32 || ed_private_scalar.len() != 32 {
        panic!("All inputs must be 32 bytes");
    }

    // Convert all inputs to Scalars
    let r_scalar = Scalar::from_bytes_mod_order(*<&[u8; 32]>::try_from(nonce).unwrap());
    let k_scalar = Scalar::from_bytes_mod_order(*<&[u8; 32]>::try_from(challenge_hash).unwrap());
    let a_scalar = Scalar::from_bytes_mod_order(*<&[u8; 32]>::try_from(ed_private_scalar).unwrap());

    // s = r + k * a
    let s_scalar = r_scalar + k_scalar * a_scalar;

    // Return s as 32-byte array
    s_scalar.to_bytes().to_vec()
}


#[wasm_bindgen]
// Compute the signature as R || S
// where R is the nonce point and S is the signature scalar
pub fn compute_signature(nonce_point: &[u8], signature_scalar: &[u8]) -> Vec<u8> {
    if nonce_point.len() != 32 || signature_scalar.len() != 32 {
        panic!("Nonce point and scalar must be 32 bytes");
    }

    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(nonce_point);       // R
    signature.extend_from_slice(signature_scalar);  // S

    signature
}

#[wasm_bindgen]
/// Verify the signature
/// Returns true if the signature is valid, false otherwise
pub fn verify_signature(signature: &[u8], message: &[u8], public_ed_key: &[u8]) -> bool {
    if signature.len() != 64 || public_ed_key.len() != 32 {
        return false;
    }

    // Try to decode signature
    let decoded_signature = match decode_xeddsa_signature(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let r = decoded_signature.r;
    let s = decoded_signature.s;

    // Decompress public key
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(public_ed_key);
    let compressed_pubkey = CompressedEdwardsY(pubkey_bytes);
    let A = match compressed_pubkey.decompress() {
        Some(point) => point,
        None => return false,
    };

    // Compute challenge hash as scalar directly
    let mut hasher = Sha512::new();
    hasher.update(&decoded_signature.r_bytes);
    hasher.update(public_ed_key);
    hasher.update(message);
    let hash_bytes = hasher.finalize();
    
    let reduced = reduce_hash_mod_l(&hash_bytes);
    let k_bytes = biguint_to_scalar_bytes(&reduced);
    let k = Scalar::from_bytes_mod_order(k_bytes);

    
    // Compute verification equation
    let SB = s * ED25519_BASEPOINT_POINT;
    let kA = k * A;
    let expected = r + kA;

    SB == expected
} 

#[wasm_bindgen]
// For testing purposes, this function performs all XEdDSA within the module to rule out JS implementation issues
pub fn test_sign_and_verify(prekey: &[u8], identity_seed: &[u8]) -> bool {

    log_bytes!("PREKEY", prekey);
    log_bytes!("IDENTITY SEED", identity_seed);

    let xeddsa = convert_x25519_to_xeddsa(identity_seed);
    let a = &xeddsa[0..32];
    let prefix = &xeddsa[32..64];

    log_bytes!("XEdDSA", xeddsa);
    log_bytes!("a", a);
    log_bytes!("prefix", prefix);

    let r = compute_determenistic_nonce(prefix, prekey);
    let R = compute_nonce_point(&r);
    let A = derive_ed25519_keypair_from_x25519(identity_seed);
    let k = compute_challenge_hash(&R, &A, prekey);
    let s = compute_signature_scaler(&r, &k, a);
    let signature = compute_signature(&R, &s);

    log_bytes!("r", r);
    log_bytes!("R", R);
    log_bytes!("A", A);
    log_bytes!("k", k);
    log_bytes!("s", s);
    log_bytes!("signature", signature);

    verify_signature(&signature, prekey, &A)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_bytes() {
        let data = b"test data";
        let hash = sha512_bytes(data);
        
        assert_eq!(hash.len(), 64);
        
        // Should be deterministic
        let hash2 = sha512_bytes(data);
        assert_eq!(hash, hash2);
        
        // Different data should produce different hash
        let hash3 = sha512_bytes(b"different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_clamp() {
        let mut key = [0xFFu8; 32];
        clamp(&mut key);
        
        // Check clamping rules
        assert_eq!(key[0] & 0x07, 0);
        assert_eq!(key[31] & 0x80, 0);
        assert_eq!(key[31] & 0x40, 0x40);
    }

    #[test]
    fn test_ed25519_l() {
        let l = ed25519_l();
        // L should be the order of the Ed25519 curve
        assert_eq!(
            l.to_string(),
            "7237005577332262213973186563042994240857116359379907606001950938285454252873"
        );
    }

    #[test]
    fn test_reduce_hash_mod_l() {
        let hash = [0xFFu8; 64];
        let reduced = reduce_hash_mod_l(&hash);
        
        let l = ed25519_l();
        assert!(reduced < l);
    }

    #[test]
    fn test_biguint_to_scalar_bytes() {
        let big = BigUint::from(12345u32);
        let bytes = biguint_to_scalar_bytes(&big);
        
        assert_eq!(bytes.len(), 32);
        
        // First few bytes should contain the value (little-endian)
        assert_eq!(bytes[0], 0x39);
        assert_eq!(bytes[1], 0x30);
    }

    #[test]
    fn test_convert_x25519_to_xeddsa() {
        let private_key = [1u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        
        assert_eq!(xeddsa.len(), 64);
        
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        
        // Check that 'a' is clamped
        assert_eq!(a[0] & 0x07, 0);
        assert_eq!(a[31] & 0x80, 0);
        assert_eq!(a[31] & 0x40, 0x40);
        
        // Should be deterministic
        let xeddsa2 = convert_x25519_to_xeddsa(&private_key);
        assert_eq!(xeddsa, xeddsa2);
        
        // Different input should produce different output
        let private_key2 = [2u8; 32];
        let xeddsa3 = convert_x25519_to_xeddsa(&private_key2);
        assert_ne!(xeddsa, xeddsa3);
    }

    #[test]
    fn test_compute_determenistic_nonce() {
        let prefix = [3u8; 32];
        let message = b"test message";
        
        let nonce = compute_determenistic_nonce(&prefix, message);
        assert_eq!(nonce.len(), 32);
        
        // Should be deterministic
        let nonce2 = compute_determenistic_nonce(&prefix, message);
        assert_eq!(nonce, nonce2);
        
        // Different message should produce different nonce
        let nonce3 = compute_determenistic_nonce(&prefix, b"different message");
        assert_ne!(nonce, nonce3);
        
        // Different prefix should produce different nonce
        let prefix2 = [4u8; 32];
        let nonce4 = compute_determenistic_nonce(&prefix2, message);
        assert_ne!(nonce, nonce4);
    }

    #[test]
    fn test_compute_nonce_point() {
        let nonce = [5u8; 32];
        let point = compute_nonce_point(&nonce);
        
        assert_eq!(point.len(), 32);
        
        // Should be deterministic
        let point2 = compute_nonce_point(&nonce);
        assert_eq!(point, point2);
        
        // Different nonce should produce different point
        let nonce2 = [6u8; 32];
        let point3 = compute_nonce_point(&nonce2);
        assert_ne!(point, point3);
    }

    #[test]
    #[should_panic(expected = "nonce_bytes must be exactly 32 bytes")]
    fn test_compute_nonce_point_invalid_length() {
        let nonce = [1u8; 16];
        compute_nonce_point(&nonce);
    }

    #[test]
    fn test_derive_ed25519_keypair_from_x25519() {
        let private_key = [7u8; 32];
        let public_key = derive_ed25519_keypair_from_x25519(&private_key);
        
        assert_eq!(public_key.len(), 32);
        
        // Should be deterministic
        let public_key2 = derive_ed25519_keypair_from_x25519(&private_key);
        assert_eq!(public_key, public_key2);
        
        // Different private key should produce different public key
        let private_key2 = [8u8; 32];
        let public_key3 = derive_ed25519_keypair_from_x25519(&private_key2);
        assert_ne!(public_key, public_key3);
    }

    #[test]
    fn test_compute_challenge_hash() {
        let nonce_point = [9u8; 32];
        let public_key = [10u8; 32];
        let message = b"test message";
        
        let challenge = compute_challenge_hash(&nonce_point, &public_key, message);
        assert_eq!(challenge.len(), 32);
        
        // Should be deterministic
        let challenge2 = compute_challenge_hash(&nonce_point, &public_key, message);
        assert_eq!(challenge, challenge2);
        
        // Different inputs should produce different challenge
        let challenge3 = compute_challenge_hash(&nonce_point, &public_key, b"different");
        assert_ne!(challenge, challenge3);
    }

    #[test]
    #[should_panic(expected = "edPrivScaler and publicEdKey must be exactly 32 bytes")]
    fn test_compute_challenge_hash_invalid_nonce_length() {
        let nonce_point = [1u8; 16];
        let public_key = [2u8; 32];
        let message = b"test";
        compute_challenge_hash(&nonce_point, &public_key, message);
    }

    #[test]
    #[should_panic(expected = "edPrivScaler and publicEdKey must be exactly 32 bytes")]
    fn test_compute_challenge_hash_invalid_pubkey_length() {
        let nonce_point = [1u8; 32];
        let public_key = [2u8; 16];
        let message = b"test";
        compute_challenge_hash(&nonce_point, &public_key, message);
    }

    #[test]
    fn test_compute_signature_scaler() {
        let nonce = [11u8; 32];
        let challenge = [12u8; 32];
        let private_scalar = [13u8; 32];
        
        let signature_scalar = compute_signature_scaler(&nonce, &challenge, &private_scalar);
        assert_eq!(signature_scalar.len(), 32);
        
        // Should be deterministic
        let signature_scalar2 = compute_signature_scaler(&nonce, &challenge, &private_scalar);
        assert_eq!(signature_scalar, signature_scalar2);
    }

    #[test]
    #[should_panic(expected = "All inputs must be 32 bytes")]
    fn test_compute_signature_scaler_invalid_length() {
        let nonce = [1u8; 16];
        let challenge = [2u8; 32];
        let private_scalar = [3u8; 32];
        compute_signature_scaler(&nonce, &challenge, &private_scalar);
    }

    #[test]
    fn test_compute_signature() {
        let nonce_point = [14u8; 32];
        let signature_scalar = [15u8; 32];
        
        let signature = compute_signature(&nonce_point, &signature_scalar);
        assert_eq!(signature.len(), 64);
        
        // First 32 bytes should be nonce_point
        assert_eq!(&signature[0..32], &nonce_point);
        // Last 32 bytes should be signature_scalar
        assert_eq!(&signature[32..64], &signature_scalar);
    }

    #[test]
    #[should_panic(expected = "Nonce point and scalar must be 32 bytes")]
    fn test_compute_signature_invalid_length() {
        let nonce_point = [1u8; 16];
        let signature_scalar = [2u8; 32];
        compute_signature(&nonce_point, &signature_scalar);
    }

    #[test]
    fn test_decode_xeddsa_signature_valid() {
        let mut signature = [0u8; 64];
        // Create a valid R point (using basepoint for simplicity)
        let r_point = ED25519_BASEPOINT_POINT.compress().to_bytes();
        signature[0..32].copy_from_slice(&r_point);
        
        // Create a valid S scalar
        let s_scalar = Scalar::from(12345u64);
        signature[32..64].copy_from_slice(&s_scalar.to_bytes());
        
        let result = decode_xeddsa_signature(&signature);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.r_bytes, r_point);
        assert_eq!(decoded.s, s_scalar);
    }

    #[test]
    fn test_decode_xeddsa_signature_invalid_length() {
        let signature = [0u8; 32];
        let result = decode_xeddsa_signature(&signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_invalid_lengths() {
        let signature = [0u8; 32];
        let message = b"test";
        let public_key = [0u8; 32];
        
        assert!(!verify_signature(&signature, message, &public_key));
        
        let signature = [0u8; 64];
        let public_key = [0u8; 16];
        assert!(!verify_signature(&signature, message, &public_key));
    }

    #[test]
    fn test_sign_and_verify_workflow() {
        // Create a private key
        let private_key = [16u8; 32];
        
        // Convert to XEdDSA
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        
        // Message to sign
        let message = b"hello world";
        
        // Compute nonce
        let r = compute_determenistic_nonce(prefix, message);
        let R = compute_nonce_point(&r);
        
        // Derive public key
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        
        // Compute challenge
        let k = compute_challenge_hash(&R, &A, message);
        
        // Compute signature scalar
        let s = compute_signature_scaler(&r, &k, a);
        
        // Create signature
        let signature = compute_signature(&R, &s);
        
        // Verify signature
        assert!(verify_signature(&signature, message, &A));
        
        // Verify fails with wrong message
        assert!(!verify_signature(&signature, b"wrong message", &A));
        
        // Verify fails with wrong public key
        let wrong_key = [17u8; 32];
        assert!(!verify_signature(&signature, message, &wrong_key));
    }

    #[test]
    fn test_sign_and_verify_multiple_messages() {
        let private_key = [18u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        
        let messages = vec![
            b"message 1".as_slice(),
            b"message 2".as_slice(),
            b"message 3".as_slice(),
        ];
        
        for message in messages {
            let r = compute_determenistic_nonce(prefix, message);
            let R = compute_nonce_point(&r);
            let k = compute_challenge_hash(&R, &A, message);
            let s = compute_signature_scaler(&r, &k, a);
            let signature = compute_signature(&R, &s);
            
            assert!(verify_signature(&signature, message, &A));
        }
    }

    #[test]
    fn test_test_sign_and_verify_integration() {
        // This test duplicates what test_sign_and_verify does without using console.log
        let prekey = [19u8; 32];
        let identity_seed = [20u8; 32];
        
        let xeddsa = convert_x25519_to_xeddsa(&identity_seed);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];

        let r = compute_determenistic_nonce(prefix, &prekey);
        let R = compute_nonce_point(&r);
        let A = derive_ed25519_keypair_from_x25519(&identity_seed);
        let k = compute_challenge_hash(&R, &A, &prekey);
        let s = compute_signature_scaler(&r, &k, a);
        let signature = compute_signature(&R, &s);

        let result = verify_signature(&signature, &prekey, &A);
        assert!(result);
    }

    #[test]
    fn test_signature_uniqueness() {
        let private_key = [21u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        
        let message1 = b"message 1";
        let message2 = b"message 2";
        
        // Sign both messages
        let r1 = compute_determenistic_nonce(prefix, message1);
        let R1 = compute_nonce_point(&r1);
        let k1 = compute_challenge_hash(&R1, &A, message1);
        let s1 = compute_signature_scaler(&r1, &k1, a);
        let sig1 = compute_signature(&R1, &s1);
        
        let r2 = compute_determenistic_nonce(prefix, message2);
        let R2 = compute_nonce_point(&r2);
        let k2 = compute_challenge_hash(&R2, &A, message2);
        let s2 = compute_signature_scaler(&r2, &k2, a);
        let sig2 = compute_signature(&R2, &s2);
        
        // Signatures should be different
        assert_ne!(sig1, sig2);
        
        // Each verifies with its own message
        assert!(verify_signature(&sig1, message1, &A));
        assert!(verify_signature(&sig2, message2, &A));
        
        // Cross-verification should fail
        assert!(!verify_signature(&sig1, message2, &A));
        assert!(!verify_signature(&sig2, message1, &A));
    }

    #[test]
    fn test_determenistic_signature() {
        let private_key = [22u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        let message = b"deterministic test";
        
        // Sign twice
        let r1 = compute_determenistic_nonce(prefix, message);
        let R1 = compute_nonce_point(&r1);
        let k1 = compute_challenge_hash(&R1, &A, message);
        let s1 = compute_signature_scaler(&r1, &k1, a);
        let sig1 = compute_signature(&R1, &s1);
        
        let r2 = compute_determenistic_nonce(prefix, message);
        let R2 = compute_nonce_point(&r2);
        let k2 = compute_challenge_hash(&R2, &A, message);
        let s2 = compute_signature_scaler(&r2, &k2, a);
        let sig2 = compute_signature(&R2, &s2);
        
        // Signatures should be identical
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_private_keys_produce_different_signatures() {
        let private_key1 = [23u8; 32];
        let private_key2 = [24u8; 32];
        let message = b"test message";
        
        // Sign with first key
        let xeddsa1 = convert_x25519_to_xeddsa(&private_key1);
        let a1 = &xeddsa1[0..32];
        let prefix1 = &xeddsa1[32..64];
        let A1 = derive_ed25519_keypair_from_x25519(&private_key1);
        
        let r1 = compute_determenistic_nonce(prefix1, message);
        let R1 = compute_nonce_point(&r1);
        let k1 = compute_challenge_hash(&R1, &A1, message);
        let s1 = compute_signature_scaler(&r1, &k1, a1);
        let sig1 = compute_signature(&R1, &s1);
        
        // Sign with second key
        let xeddsa2 = convert_x25519_to_xeddsa(&private_key2);
        let a2 = &xeddsa2[0..32];
        let prefix2 = &xeddsa2[32..64];
        let A2 = derive_ed25519_keypair_from_x25519(&private_key2);
        
        let r2 = compute_determenistic_nonce(prefix2, message);
        let R2 = compute_nonce_point(&r2);
        let k2 = compute_challenge_hash(&R2, &A2, message);
        let s2 = compute_signature_scaler(&r2, &k2, a2);
        let sig2 = compute_signature(&R2, &s2);
        
        // Signatures should be different
        assert_ne!(sig1, sig2);
        
        // Each verifies with its own public key
        assert!(verify_signature(&sig1, message, &A1));
        assert!(verify_signature(&sig2, message, &A2));
        
        // Cross-verification should fail
        assert!(!verify_signature(&sig1, message, &A2));
        assert!(!verify_signature(&sig2, message, &A1));
    }

    #[test]
    fn test_empty_message_signature() {
        let private_key = [25u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        let message = b"";
        
        let r = compute_determenistic_nonce(prefix, message);
        let R = compute_nonce_point(&r);
        let k = compute_challenge_hash(&R, &A, message);
        let s = compute_signature_scaler(&r, &k, a);
        let signature = compute_signature(&R, &s);
        
        assert!(verify_signature(&signature, message, &A));
    }

    #[test]
    fn test_large_message_signature() {
        let private_key = [26u8; 32];
        let xeddsa = convert_x25519_to_xeddsa(&private_key);
        let a = &xeddsa[0..32];
        let prefix = &xeddsa[32..64];
        let A = derive_ed25519_keypair_from_x25519(&private_key);
        let message = vec![0x42u8; 10000]; // 10KB message
        
        let r = compute_determenistic_nonce(prefix, &message);
        let R = compute_nonce_point(&r);
        let k = compute_challenge_hash(&R, &A, &message);
        let s = compute_signature_scaler(&r, &k, a);
        let signature = compute_signature(&R, &s);
        
        assert!(verify_signature(&signature, &message, &A));
    }
}