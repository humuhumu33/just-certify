//! `gen-issuer-key` — print a fresh Ed25519 keypair in the three
//! shapes the service operator needs:
//!
//! * `private_key_b64` — for `SEM_IPLD_ISSUER_KEY_B64`. Base64 of the
//!   raw 32-byte seed (not multibase).
//! * `public_key_multibase` — for `did.json`'s `publicKeyMultibase`.
//!   W3C Multikey encoding of Ed25519 (multicodec `0xed 0x01` + 32
//!   bytes, base58btc multibase — the `z6Mk…` form).
//! * `verification_method` — the fixed DID URL used throughout this
//!   release. Printed as a reminder.
//!
//! # One-time operator flow
//!
//! ```sh
//! cargo run --release -p uor-vc-crypto --bin gen-issuer-key
//! # → paste private_key_b64  into SEM_IPLD_ISSUER_KEY_B64
//! # → paste public_key_multibase into docs/did/did.json
//! ```
//!
//! Running this binary twice produces two different key pairs — it
//! is not deterministic. Generate once, paste to both places, commit
//! the updated `did.json`, then wipe the stdout buffer.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_seed = signing_key.to_bytes(); // 32 bytes
    let private_b64 = base64::engine::general_purpose::STANDARD.encode(private_seed);

    let public_multikey = uor_vc_crypto::ed25519_public_multikey(&verifying_key);

    // Self-check: re-derive the public key from the private seed and
    // confirm it matches. The operator should see "self_check: ok".
    let rederived = SigningKey::from_bytes(&private_seed).verifying_key();
    let self_check = if rederived.to_bytes() == verifying_key.to_bytes() {
        "ok"
    } else {
        "FAILED (internal bug — do not use this key)"
    };

    println!("private_key_b64:      {private_b64}");
    println!("public_key_multibase: {public_multikey}");
    println!("verification_method:  did:web:uor.foundation#key-1");
    println!("self_check:           {self_check}");
}
