import { execSync } from 'child_process'
import { cpSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'fs'
import { join } from 'path'
import { fileURLToPath } from 'url'

const ROOT = fileURLToPath(new URL('.', import.meta.url))
const PKG  = join(ROOT, 'pkg')

const crates = [
  { dir: 'aes',    name: 'aes'    },
  { dir: 'x25519', name: 'x25519' },
  { dir: 'xeddsa', name: 'xeddsa' },
]

// Preserve pkg metadata before wiping                                      

const preserve = ['package.json', 'README.md', 'EchoProtocolLogo.png']
const saved = {}
for (const f of preserve) {
  const p = join(PKG, f)
  if (existsSync(p)) saved[f] = readFileSync(p)
}

rmSync(PKG, { recursive: true, force: true })
mkdirSync(PKG)

for (const [f, buf] of Object.entries(saved)) {
  writeFileSync(join(PKG, f), buf)
}

// Build each Rust crate                                                      

for (const { dir, name } of crates) {
  const crateDir = join(ROOT, dir)
  console.log(`\nBuilding ${dir}...`)
  execSync('wasm-pack build --target web', { cwd: crateDir, stdio: 'inherit' })

  const src = join(crateDir, 'pkg')

  // Fix wasm URL reference then copy JS
  let js = readFileSync(join(src, `${name}.js`), 'utf8')
  js = js.replace(/new URL\('[^']*_bg\.wasm'/, `new URL('${name}_bg.wasm'`)
  writeFileSync(join(PKG, `${name}.js`), js)

  // Copy wasm binary + its type declaration
  cpSync(join(src, `${name}_bg.wasm`),       join(PKG, `${name}_bg.wasm`))
  cpSync(join(src, `${name}_bg.wasm.d.ts`),  join(PKG, `${name}_bg.wasm.d.ts`))

  // Copy TS declaration
  cpSync(join(src, `${name}.d.ts`), join(PKG, `${name}.d.ts`))
}

// Write unified index.js                                                     

writeFileSync(join(PKG, 'index.js'), `\
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
  hkdf_extract,
  hkdf_expand,
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
  hkdf_extract,
  hkdf_expand,
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
`)

// Write unified index.d.ts                                                   

writeFileSync(join(PKG, 'index.d.ts'), `\
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
export function hkdf_extract(salt: Uint8Array, input_key_material: Uint8Array): Uint8Array;
export function hkdf_expand(pseudo_random_key: Uint8Array, info: Uint8Array, output_len: number): Uint8Array;

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
`)

console.log('\nDone. pkg/ is ready.')
