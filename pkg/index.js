import initAes, {
  encrypt, decrypt,
  encrypt_aad, decrypt_aad,
  encrypt_aad_bytes, decrypt_aad_bytes,
} from './aes.js'

import initX25519, {
  derive_symmetric_key,
  diffie_hellman,
  generate_ed25519_public_key,
  generate_ed25519_private_key,
  derive_x25519_from_ed25519_private,
  generate_public_prekey,
  generate_private_prekey,
  generate_public_ephemeral_key,
  generate_private_ephemeral_key,
  hkdf_derive,
} from './x25519.js'

import initXeddsa, {
  convert_x25519_to_xeddsa,
  compute_determenistic_nonce,
  compute_nonce_point,
  derive_ed25519_keypair_from_x25519,
  compute_challenge_hash,
  compute_signature_scaler,
  compute_signature,
  verify_signature,
  test_sign_and_verify,
} from './xeddsa.js'

export async function init() {
  await Promise.all([initAes(), initX25519(), initXeddsa()])
}

// AES-GCM
export {
  encrypt, decrypt,
  encrypt_aad, decrypt_aad,
  encrypt_aad_bytes, decrypt_aad_bytes,
}

// X25519 key exchange + HKDF
export {
  derive_symmetric_key,
  diffie_hellman,
  generate_ed25519_public_key,
  generate_ed25519_private_key,
  derive_x25519_from_ed25519_private,
  generate_public_prekey,
  generate_private_prekey,
  generate_public_ephemeral_key,
  generate_private_ephemeral_key,
  hkdf_derive,
}

// XEdDSA signatures
export {
  convert_x25519_to_xeddsa,
  compute_determenistic_nonce,
  compute_nonce_point,
  derive_ed25519_keypair_from_x25519,
  compute_challenge_hash,
  compute_signature_scaler,
  compute_signature,
  verify_signature,
  test_sign_and_verify,
}

export default init
