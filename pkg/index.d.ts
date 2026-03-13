/* tslint:disable */
/* eslint-disable */

//    AES-GCM                                                                   
export function encrypt(text: string, key: Uint8Array, nonce: Uint8Array): string;
export function decrypt(text: string, key: Uint8Array, nonce: Uint8Array): string;
export function encrypt_aad(text: string, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): string;
export function decrypt_aad(cipher_hex: string, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): string;
export function encrypt_aad_bytes(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;
export function decrypt_aad_bytes(cipher_hex: Uint8Array, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Uint8Array;

//    X25519 Key Exchange + HKDF                                                
export function derive_symmetric_key(shared_secret: Uint8Array): Uint8Array;
export function diffie_hellman(my_private_key_bytes: Uint8Array, their_public_key_bytes: Uint8Array): Uint8Array;
export function generate_ed25519_public_key(seed: Uint8Array): Uint8Array;
export function generate_ed25519_private_key(js_random_bytes: Uint8Array): Uint8Array;
export function derive_x25519_from_ed25519_private(ed25519_seed: Uint8Array): any;
export function generate_public_prekey(private_prekey_bytes: Uint8Array): Uint8Array;
export function generate_private_prekey(js_random_bytes: Uint8Array): Uint8Array;
export function generate_public_ephemeral_key(private_prekey_bytes: Uint8Array): Uint8Array;
export function generate_private_ephemeral_key(js_random_bytes: Uint8Array): Uint8Array;
export function hkdf_derive(input_key_material: Uint8Array, salt: Uint8Array, info: Uint8Array, output_len: number): Uint8Array;

//    XEdDSA Signatures                                                         
export function convert_x25519_to_xeddsa(private_key_bytes: Uint8Array): Uint8Array;
export function compute_determenistic_nonce(prefix: Uint8Array, message: Uint8Array): Uint8Array;
export function compute_nonce_point(nonce_bytes: Uint8Array): Uint8Array;
export function derive_ed25519_keypair_from_x25519(private_key_bytes: Uint8Array): Uint8Array;
export function compute_challenge_hash(nonce_point: Uint8Array, public_ed_key: Uint8Array, message: Uint8Array): Uint8Array;
export function compute_signature_scaler(nonce: Uint8Array, challenge_hash: Uint8Array, ed_private_scalar: Uint8Array): Uint8Array;
export function compute_signature(nonce_point: Uint8Array, signature_scalar: Uint8Array): Uint8Array;
export function verify_signature(signature: Uint8Array, message: Uint8Array, public_ed_key: Uint8Array): boolean;
export function test_sign_and_verify(prekey: Uint8Array, identity_seed: Uint8Array): boolean;

//    Initialization                                                            
export function init(): Promise<void>;
export default init;
