# Changelog — uor-vc-crypto

## 0.2.0 — Signed cryptosuite

Companion release to `sem-ipld-service` v0.4.0.

### Added

- **`uor-dag-cbor-ed25519-2025`** cryptosuite: Ed25519 signature
  over the 34-byte multihash of the canonical form. Shares
  `canonicalize_for_proof` with the unsigned variant — byte-
  identical canonical bytes for the same `(document, options)`.
- **`verify()` dispatcher** inspects `proof.cryptosuite` and
  routes to the matching verifier. Accepts an optional
  `VerificationKeyResolver` for the signed variant.
- **`VerificationKeyResolver` trait** — caller plugs in DID
  resolution.
- **`ed25519_public_multikey` / `ed25519_public_from_multikey`**
  helpers for the W3C Multikey format (`z6Mk…`).
- **`gen-issuer-key` binary** — prints base64 private seed +
  Multikey public key + verification method URL + a self-check
  line.
- **`verify_signed_smoke_test` binary** — verifies a signed VC,
  resolving the public key by fetching the running service's
  `/v1/health` endpoint.
- **`tests/test_vectors.rs`** — three pinned test vectors
  (minimal VC, nested credentialSubject, array of subjects)
  referenced by the cryptosuite specification.

### Changed

- `CryptoError::ProofMismatch` preserved, joined by
  `SignatureInvalid`, `UnresolvableVerificationMethod`, and
  `KeyRequired`.
- `ProofOptions` is now a type alias for the shared `CommonOptions`
  struct; existing v0.1.0 call sites compile unchanged.
- Crate-level `#![allow(clippy::result_large_err)]` documented
  in the module header — `ProofMismatch` legitimately carries
  two CIDs.

### Breaking changes

None at the API boundary. The v0.1.0 `sign` and `verify`
functions are preserved as aliases; `verify(doc)` → `verify(doc, None)`
in the v0.2.0 signature, but call sites compile without edits
because the original `verify(doc)` is also kept. `CRYPTOSUITE_NAME`
aliases `CRYPTOSUITE_UNSIGNED`.

## 0.1.0 — Initial release

Companion release to `sem-ipld-service` v0.3.0.

- `uor-dag-cbor-2025` cryptosuite: unsigned, content-addressed
  tamper-evidence.
- DAG-CBOR canonicalization via `serde_ipld_dagcbor`.
- `sign` / `verify` functions.
- `ProofOptions` + `CryptoError`.
- `verify_vc_smoke_test` binary.
- Six unit tests covering round-trip, tamper detection, wrong-
  cryptosuite rejection, nested/array documents, and missing-
  field errors.
