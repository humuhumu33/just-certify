# uor-vc-crypto

**Two W3C Data Integrity 1.0 cryptosuites sharing one
canonicalization.**

```rust
use uor_vc_crypto::{sign_unsigned, sign_signed, verify, ProofOptions,
                    SignedProofOptions, SignedVerifyOptions,
                    VerificationKeyResolver};
use ed25519_dalek::SigningKey;

// 1. Unsigned ("tamper-evidence") — the CID IS the proof.
let doc = serde_json::json!({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type":     "VerifiableCredential",
    "credentialSubject": { "id": "urn:example:ada" }
});
let signed = sign_unsigned(&doc, &ProofOptions::assertion("did:web:example#key"))?;
// signed.proof.proofValue starts with "bafyrei…"

verify(&signed, None)?;   // unsigned variant needs no resolver

// 2. Signed ("tamper-evidence + authenticity").
let key = SigningKey::generate(&mut rand_core::OsRng);
let signed = sign_signed(&doc, &SignedProofOptions {
    common:      ProofOptions::assertion("did:web:example#key"),
    signing_key: key.clone(),
})?;
// signed.proof.proofValue starts with "z…" (multibase Ed25519 sig)

// Verify (caller supplies the public key).
uor_vc_crypto::verify_signed(
    &signed,
    &SignedVerifyOptions { verifying_key: key.verifying_key() },
)?;
```

## The two cryptosuites at a glance

| | `uor-dag-cbor-2025` | `uor-dag-cbor-ed25519-2025` |
|---|---|---|
| `proof.proofValue` | CID of canonical form (`bafyrei…`) | Ed25519 sig over the 34-byte CID multihash (`z…`) |
| Needs a key to sign? | No | Yes — 32-byte Ed25519 seed |
| Needs a key to verify? | No | Yes — public key (caller resolves `verificationMethod`) |
| Detects tampering? | Yes | Yes |
| Detects forgery? | **No** (anyone with the bytes computes the proof) | Yes |
| Use in | Single-writer / trusted-cluster | Federated / multi-party / EUDI |

## API surface

```rust
// Sign / verify — direct calls.
pub fn sign_unsigned   (doc: &Value, opts: &ProofOptions)         -> Result<Value>;
pub fn verify_unsigned (doc: &Value)                              -> Result<()>;
pub fn sign_signed     (doc: &Value, opts: &SignedProofOptions)   -> Result<Value>;
pub fn verify_signed   (doc: &Value, opts: &SignedVerifyOptions)  -> Result<()>;

// Dispatcher — inspects proof.cryptosuite and routes.
pub fn verify(
    doc:      &Value,
    resolver: Option<&dyn VerificationKeyResolver>,
) -> Result<()>;

// Multikey (W3C) helpers for the Ed25519 pubkey format.
pub fn ed25519_public_multikey   (key: &VerifyingKey) -> String;      // "z6Mk…"
pub fn ed25519_public_from_multikey(s: &str)          -> Result<VerifyingKey>;

pub const CRYPTOSUITE_UNSIGNED: &str = "uor-dag-cbor-2025";
pub const CRYPTOSUITE_SIGNED:   &str = "uor-dag-cbor-ed25519-2025";
```

A `VerificationKeyResolver` trait lets the caller plug in their
DID resolver:

```rust
pub trait VerificationKeyResolver {
    fn resolve(&self, verification_method: &str) -> Result<VerifyingKey, CryptoError>;
}
```

## Binaries

| Binary | Purpose |
|---|---|
| `gen-issuer-key` | Generates a fresh Ed25519 keypair and prints the private seed (base64) + W3C Multikey public key (`z6Mk…`). |
| `verify_vc_smoke_test` | Reads a VC from argv; calls `verify(..., None)` (unsigned path). |
| `verify_signed_smoke_test` | Reads a VC from argv; fetches the public key from a running `sem-ipld-service` at `/v1/health`; calls `verify(..., Some(resolver))`. |

## Design pointers

- Both cryptosuites canonicalize through a single shared helper
  `canonicalize_for_proof` — the byte-identical canonical form is
  the invariant documented in the cryptosuite spec and tested by
  `d3_canonical_bytes_byte_identical_across_variants`.
- The unsigned variant's `proofValue` is a CIDv1 text form
  (multibase base32 lower, `b` prefix). The signed variant's
  `proofValue` is multibase base58btc (`z` prefix) of the raw
  64-byte Ed25519 signature over the 34-byte multihash.
- No DID resolution is performed in-tree. Applications that need
  to resolve `verificationMethod` implement
  `VerificationKeyResolver` themselves.

## Cryptosuite specification

The full W3C-style specification for the unsigned variant is at
[`sem-ipld-service/docs/specs/uor-dag-cbor-2025.md`](../sem-ipld-service/docs/specs/uor-dag-cbor-2025.md).
A spec document for the signed variant is planned for v0.2.1 /
v0.3.0 of this crate after its own external review cycle.

## Anchors

- [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
  — the proof-suite framework this crate implements.
- [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  — the credential shape the cryptosuites secure.
- [IPLD DAG-CBOR](https://ipld.io/specs/codecs/dag-cbor/spec/) —
  the canonicalization.
- [multiformats/cid](https://github.com/multiformats/cid),
  [multihash](https://github.com/multiformats/multihash),
  [multibase](https://github.com/multiformats/multibase) — the
  content-addressing primitives used for `proofValue`.

## License

Apache-2.0.
