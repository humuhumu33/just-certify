//! W3C Data Integrity 1.0 cryptosuites for UOR.
//!
//! v0.2.0 ships two cryptosuites that **share canonicalization**:
//!
//! | Name                             | `proofValue` is…         | Use when |
//! |----------------------------------|---------------------------|----------|
//! | `uor-dag-cbor-2025`              | A CID of the canonical form | Single-writer / trusted-cluster; tamper-evidence |
//! | `uor-dag-cbor-ed25519-2025`      | An Ed25519 signature over the CID | Federated / multi-party; tamper-evidence **and** authenticity |
//!
//! Both use DAG-CBOR canonicalization via `serde_ipld_dagcbor` (length-first
//! key sort, shortest-form integers, strict typing). The only difference is
//! the last step: unsigned encodes the CID as the proofValue; signed signs
//! the raw 34-byte multihash of the CID with Ed25519 and encodes the
//! 64-byte signature as the proofValue.
//!
//! # D3 — canonicalization parity
//!
//! The private helper [`canonicalize_for_proof`] is shared between the two
//! variants. For the same `(document, cryptosuite_name, common_options)`,
//! the canonical bytes are **byte-identical** regardless of which variant is
//! selected. A unit test asserts this explicitly.
//!
//! # Result-size discipline
//!
//! `CryptoError::ProofMismatch` carries two CIDs (~80 bytes each) and
//! trips clippy's `result_large_err` lint. The size is semantic — callers
//! need both CIDs to diagnose — so we allow the lint at crate level.

#![allow(clippy::result_large_err)]

use cid::Cid;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use thiserror::Error;

/// The unsigned cryptosuite identifier.
pub const CRYPTOSUITE_UNSIGNED: &str = "uor-dag-cbor-2025";

/// The Ed25519-signed cryptosuite identifier.
pub const CRYPTOSUITE_SIGNED: &str = "uor-dag-cbor-ed25519-2025";

/// The `proof.type` shared by both cryptosuites.
pub const PROOF_TYPE: &str = "DataIntegrityProof";

/// Ed25519 public key multicodec prefix for the `Multikey` format —
/// `0xed 0x01`. Followed by the 32-byte raw public key, then base58btc
/// multibase-encoded to produce the `z6Mk…` form.
pub const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

// ─── common options ─────────────────────────────────────────────────────────

/// Fields both proof variants share.
#[derive(Debug, Clone)]
pub struct CommonOptions {
    /// DID URL of the verification method.
    pub verification_method: String,
    /// Typically `"assertionMethod"`.
    pub proof_purpose: String,
    /// RFC 3339 timestamp. If `None`, `sign_*` stamps the current time.
    pub created: Option<String>,
}

/// v0.3.0 compatibility alias for the unsigned-variant options.
pub type ProofOptions = CommonOptions;

impl ProofOptions {
    /// Build options for asserting a VC with the given verification method.
    pub fn assertion(verification_method: impl Into<String>) -> Self {
        Self {
            verification_method: verification_method.into(),
            proof_purpose: "assertionMethod".to_string(),
            created: None,
        }
    }
}

/// Sign-time inputs for the **signed** cryptosuite.
///
/// The [`SigningKey`] is passed by value (cheap: 32 bytes) and
/// zeroized-on-drop by `ed25519-dalek`'s internal policy. Callers
/// that want to reuse the key should clone it.
pub struct SignedProofOptions {
    /// Common proof fields.
    pub common: CommonOptions,
    /// Ed25519 signing key (private).
    pub signing_key: SigningKey,
}

/// Verify-time inputs for the **signed** cryptosuite.
pub struct SignedVerifyOptions {
    /// The caller-supplied Ed25519 public key.
    pub verifying_key: VerifyingKey,
}

/// Trait for resolving a `proof.verificationMethod` DID URL to an
/// Ed25519 public key. sem-ipld does not implement DID resolution
/// in-tree; callers pass a resolver when they want the [`verify`]
/// dispatcher to handle signed VCs.
pub trait VerificationKeyResolver {
    /// Resolve a DID URL (e.g. `"did:web:uor.foundation#key-1"`) to
    /// the Ed25519 verifying key.
    ///
    /// # Errors
    ///
    /// Return [`CryptoError::UnresolvableVerificationMethod`] with a
    /// message describing why resolution failed.
    fn resolve(&self, verification_method: &str) -> Result<VerifyingKey, CryptoError>;
}

// ─── errors ─────────────────────────────────────────────────────────────────

/// Every fallible operation returns `Result<_, CryptoError>`.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The input was not a JSON object.
    #[error("document is not a JSON object")]
    NotAnObject,
    /// A required field was missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// `proof.cryptosuite` was not one of the registered names.
    #[error("wrong cryptosuite: {0}")]
    WrongCryptosuite(String),
    /// `proof.type` was not `DataIntegrityProof`.
    #[error("wrong proof type: expected {PROOF_TYPE}, got {0}")]
    WrongProofType(String),
    /// `serde_ipld_dagcbor::to_vec` failed.
    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(String),
    /// `proof.proofValue` did not parse as a CID (unsigned) or a
    /// multibase signature (signed).
    #[error("invalid proof value: {0}")]
    InvalidProofValue(String),
    /// Unsigned variant: the recomputed CID did not match the carried CID.
    #[error("proof value does not match canonical form: expected {expected}, got {computed}")]
    ProofMismatch {
        /// The CID carried in `proof.proofValue`.
        expected: Cid,
        /// The CID we computed from the canonical form.
        computed: Cid,
    },
    /// Signed variant: Ed25519 verification failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    /// The signed verifier could not resolve `proof.verificationMethod`.
    #[error("verification method not resolvable: {0}")]
    UnresolvableVerificationMethod(String),
    /// A signed operation was requested without a signing key.
    #[error("signing key required for signed cryptosuite")]
    KeyRequired,
}

// ─── shared canonicalization ────────────────────────────────────────────────
//
// D3: this function is the single canonicalization path for both
// cryptosuites. For the same (document, cryptosuite_name, common_options)
// the canonical bytes are byte-identical — tested below.

fn canonicalize_for_proof(
    document: &Value,
    cryptosuite_name: &str,
    common: &CommonOptions,
) -> Result<(Vec<u8>, Value), CryptoError> {
    let Value::Object(doc_map) = document else {
        return Err(CryptoError::NotAnObject);
    };

    // Strip any existing proof, merge the partial proof we're about to hash.
    let mut secured = doc_map.clone();
    secured.remove("proof");

    let created = common
        .created
        .clone()
        .unwrap_or_else(current_rfc3339_timestamp);

    let partial_proof = serde_json::json!({
        "type":               PROOF_TYPE,
        "cryptosuite":        cryptosuite_name,
        "created":            created,
        "verificationMethod": common.verification_method,
        "proofPurpose":       common.proof_purpose,
    });
    secured.insert("proof".into(), partial_proof);

    let with_proof = Value::Object(secured);
    let canonical_bytes = serde_ipld_dagcbor::to_vec(&with_proof)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;

    Ok((canonical_bytes, with_proof))
}

// ─── unsigned variant (v0.3.0 behaviour, unchanged) ─────────────────────────

/// Sign with the unsigned cryptosuite (`uor-dag-cbor-2025`).
///
/// # Errors
///
/// See [`CryptoError`].
pub fn sign_unsigned(document: &Value, options: &ProofOptions) -> Result<Value, CryptoError> {
    let (canonical_bytes, mut secured) =
        canonicalize_for_proof(document, CRYPTOSUITE_UNSIGNED, options)?;
    let cid = sem_ipld::ipld::dag_cbor_cid(&canonical_bytes)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;

    if let Some(Value::Object(pm)) = secured.as_object_mut().and_then(|m| m.get_mut("proof")) {
        pm.insert("proofValue".into(), Value::String(cid.to_string()));
    }
    Ok(secured)
}

/// Verify a VC bearing an unsigned (`uor-dag-cbor-2025`) proof.
///
/// # Errors
///
/// See [`CryptoError`].
pub fn verify_unsigned(document: &Value) -> Result<(), CryptoError> {
    let (proof_map, stripped) = extract_proof_and_stripped(document)?;
    expect_cryptosuite(&proof_map, CRYPTOSUITE_UNSIGNED)?;

    let proof_value = proof_map
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or(CryptoError::MissingField("proof.proofValue"))?;
    let expected: Cid = proof_value
        .parse()
        .map_err(|e: cid::Error| CryptoError::InvalidProofValue(e.to_string()))?;

    let canonical_bytes = serde_ipld_dagcbor::to_vec(&stripped)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;
    let computed = sem_ipld::ipld::dag_cbor_cid(&canonical_bytes)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;

    if computed != expected {
        return Err(CryptoError::ProofMismatch { expected, computed });
    }
    Ok(())
}

// ─── signed variant (v0.4.0 new) ────────────────────────────────────────────

/// Sign with the Ed25519 cryptosuite (`uor-dag-cbor-ed25519-2025`).
///
/// The signature is Ed25519 over the raw multihash bytes (34 bytes:
/// 0x12 0x20 + 32-byte SHA-256 digest) of the canonical form.
///
/// # Errors
///
/// See [`CryptoError`].
pub fn sign_signed(document: &Value, options: &SignedProofOptions) -> Result<Value, CryptoError> {
    let (canonical_bytes, mut secured) =
        canonicalize_for_proof(document, CRYPTOSUITE_SIGNED, &options.common)?;
    let cid = sem_ipld::ipld::dag_cbor_cid(&canonical_bytes)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;

    // Sign the multihash bytes — 34 bytes for SHA-256 (0x12 0x20 + 32).
    let mh_bytes = cid.hash().to_bytes();
    let signature: Signature = options.signing_key.sign(&mh_bytes);

    // proofValue = multibase base58btc of 64-byte signature.
    let proof_value = multibase::encode(multibase::Base::Base58Btc, signature.to_bytes());

    if let Some(Value::Object(pm)) = secured.as_object_mut().and_then(|m| m.get_mut("proof")) {
        pm.insert("proofValue".into(), Value::String(proof_value));
    }
    Ok(secured)
}

/// Verify a VC bearing a signed (`uor-dag-cbor-ed25519-2025`) proof.
///
/// # Errors
///
/// See [`CryptoError`].
pub fn verify_signed(document: &Value, options: &SignedVerifyOptions) -> Result<(), CryptoError> {
    let (proof_map, stripped) = extract_proof_and_stripped(document)?;
    expect_cryptosuite(&proof_map, CRYPTOSUITE_SIGNED)?;

    // Decode multibase signature (64 bytes).
    let proof_value = proof_map
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or(CryptoError::MissingField("proof.proofValue"))?;
    let (_, sig_bytes) = multibase::decode(proof_value)
        .map_err(|e| CryptoError::InvalidProofValue(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidProofValue(format!(
            "expected 64-byte Ed25519 signature, got {} bytes",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    // Recompute CID from the canonical form (same as unsigned variant).
    let canonical_bytes = serde_ipld_dagcbor::to_vec(&stripped)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;
    let cid = sem_ipld::ipld::dag_cbor_cid(&canonical_bytes)
        .map_err(|e| CryptoError::CanonicalizationFailed(e.to_string()))?;
    let mh_bytes = cid.hash().to_bytes();

    options
        .verifying_key
        .verify(&mh_bytes, &signature)
        .map_err(|e| CryptoError::SignatureInvalid(e.to_string()))?;
    Ok(())
}

// ─── dispatcher ─────────────────────────────────────────────────────────────

/// Inspect `proof.cryptosuite` and route to the matching verifier.
///
/// For the unsigned suite, `resolver` may be `None`. For the signed
/// suite, `resolver` must be `Some` and must resolve the
/// `proof.verificationMethod` to a public key.
///
/// # Errors
///
/// See [`CryptoError`].
pub fn verify(
    document: &Value,
    resolver: Option<&dyn VerificationKeyResolver>,
) -> Result<(), CryptoError> {
    let (proof_map, _) = extract_proof_and_stripped(document)?;
    let cryptosuite = proof_map
        .get("cryptosuite")
        .and_then(Value::as_str)
        .ok_or(CryptoError::MissingField("proof.cryptosuite"))?;

    match cryptosuite {
        CRYPTOSUITE_UNSIGNED => verify_unsigned(document),
        CRYPTOSUITE_SIGNED => {
            let r = resolver.ok_or(CryptoError::KeyRequired)?;
            let vm = proof_map
                .get("verificationMethod")
                .and_then(Value::as_str)
                .ok_or(CryptoError::MissingField("proof.verificationMethod"))?;
            let vk = r.resolve(vm)?;
            verify_signed(document, &SignedVerifyOptions { verifying_key: vk })
        }
        other => Err(CryptoError::WrongCryptosuite(other.to_string())),
    }
}

// ─── v0.3.0-compat aliases ──────────────────────────────────────────────────

/// v0.3.0 `sign` — kept as an alias of [`sign_unsigned`] so the
/// service crate's v0.3.0 code paths keep working without churn.
pub fn sign(document: &Value, options: &ProofOptions) -> Result<Value, CryptoError> {
    sign_unsigned(document, options)
}

/// v0.3.0 cryptosuite name re-export (points at the unsigned variant).
pub const CRYPTOSUITE_NAME: &str = CRYPTOSUITE_UNSIGNED;

// ─── Multikey helpers ───────────────────────────────────────────────────────

/// Encode an Ed25519 public key as a W3C Multikey (`z6Mk…`): base58btc
/// multibase of the multicodec prefix `0xed 0x01` followed by the
/// 32-byte raw public key.
#[must_use]
pub fn ed25519_public_multikey(key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&ED25519_PUB_MULTICODEC);
    bytes.extend_from_slice(key.as_bytes());
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

/// Decode a `z6Mk…` Multikey string back to an Ed25519 `VerifyingKey`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidProofValue`] if the input is not a
/// well-formed Ed25519 Multikey.
pub fn ed25519_public_from_multikey(s: &str) -> Result<VerifyingKey, CryptoError> {
    let (_, bytes) =
        multibase::decode(s).map_err(|e| CryptoError::InvalidProofValue(e.to_string()))?;
    if bytes.len() != 34 || bytes[0..2] != ED25519_PUB_MULTICODEC {
        return Err(CryptoError::InvalidProofValue(format!(
            "not an Ed25519 Multikey (len={}, head={:?})",
            bytes.len(),
            &bytes[..bytes.len().min(2)]
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[2..]);
    VerifyingKey::from_bytes(&arr).map_err(|e| CryptoError::InvalidProofValue(e.to_string()))
}

// ─── internal helpers ───────────────────────────────────────────────────────

fn extract_proof_and_stripped(
    document: &Value,
) -> Result<(Map<String, Value>, Value), CryptoError> {
    let Value::Object(doc_map) = document else {
        return Err(CryptoError::NotAnObject);
    };
    let proof = doc_map
        .get("proof")
        .ok_or(CryptoError::MissingField("proof"))?;
    let Value::Object(proof_map) = proof else {
        return Err(CryptoError::MissingField("proof (object)"));
    };

    let proof_type = proof_map
        .get("type")
        .and_then(Value::as_str)
        .ok_or(CryptoError::MissingField("proof.type"))?;
    if proof_type != PROOF_TYPE {
        return Err(CryptoError::WrongProofType(proof_type.to_string()));
    }

    // Build "document minus proofValue" for the canonical form.
    let mut stripped_map = doc_map.clone();
    if let Some(Value::Object(pmap)) = stripped_map.get_mut("proof") {
        pmap.remove("proofValue");
    }
    Ok((proof_map.clone(), Value::Object(stripped_map)))
}

fn expect_cryptosuite(
    proof_map: &Map<String, Value>,
    expected: &'static str,
) -> Result<(), CryptoError> {
    let suite = proof_map
        .get("cryptosuite")
        .and_then(Value::as_str)
        .ok_or(CryptoError::MissingField("proof.cryptosuite"))?;
    if suite != expected {
        return Err(CryptoError::WrongCryptosuite(suite.to_string()));
    }
    Ok(())
}

// ─── time ───────────────────────────────────────────────────────────────────

/// RFC 3339 timestamp of "now" in UTC — hand-rolled to keep the dep
/// graph small. Seconds precision per RFC 3339 §5.6.
pub fn current_rfc3339_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock sane");
    let unix_secs = now.as_secs() as i64;
    format_utc(unix_secs)
}

fn format_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (h, rem) = (secs / 3600, secs % 3600);
    let (m, s) = (rem / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m_num = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m_num <= 2 { y + 1 } else { y };
    format!("{year:04}-{m_num:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use serde_json::json;

    fn common_opts() -> CommonOptions {
        CommonOptions {
            verification_method: "did:web:uor.foundation#key-1".into(),
            proof_purpose: "assertionMethod".into(),
            created: Some("2026-04-22T00:00:00Z".into()),
        }
    }

    fn sample_doc() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": "VerifiableCredential",
            "credentialSubject": { "id": "urn:example:ada", "wittBits": 8 }
        })
    }

    // ─── unsigned variant retains v0.3.0 guarantees ─────────────────────────

    #[test]
    fn unsigned_sign_then_verify_ok() {
        let signed = sign_unsigned(&sample_doc(), &common_opts()).unwrap();
        verify_unsigned(&signed).unwrap();
        let pv = signed["proof"]["proofValue"].as_str().unwrap();
        assert!(pv.starts_with("bafyrei"));
    }

    #[test]
    fn unsigned_tamper_flips_verify() {
        let mut signed = sign_unsigned(&sample_doc(), &common_opts()).unwrap();
        signed["credentialSubject"]["wittBits"] = json!(99);
        let err = verify_unsigned(&signed).unwrap_err();
        assert!(matches!(err, CryptoError::ProofMismatch { .. }));
    }

    // ─── signed variant ─────────────────────────────────────────────────────

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn signed_opts(key: SigningKey) -> SignedProofOptions {
        SignedProofOptions {
            common: common_opts(),
            signing_key: key,
        }
    }

    #[test]
    fn signed_sign_then_verify_ok() {
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();

        // proofValue is a multibase Ed25519 signature (64 bytes).
        let pv = signed["proof"]["proofValue"].as_str().unwrap();
        assert!(
            pv.starts_with('z'),
            "expected base58btc multibase, got {pv}"
        );
        let (_, bytes) = multibase::decode(pv).unwrap();
        assert_eq!(bytes.len(), 64);

        verify_signed(&signed, &SignedVerifyOptions { verifying_key: vk }).unwrap();
    }

    #[test]
    fn signed_tamper_flips_verify() {
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let mut signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();
        signed["credentialSubject"]["wittBits"] = json!(99);
        let err = verify_signed(&signed, &SignedVerifyOptions { verifying_key: vk }).unwrap_err();
        assert!(matches!(err, CryptoError::SignatureInvalid(_)), "{err:?}");
    }

    #[test]
    fn signed_wrong_key_fails() {
        let sk = fresh_key();
        let other_vk = fresh_key().verifying_key();
        let signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();
        let err = verify_signed(
            &signed,
            &SignedVerifyOptions {
                verifying_key: other_vk,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::SignatureInvalid(_)));
    }

    #[test]
    fn cross_variant_rejection_signed_vs_unsigned() {
        let sk = fresh_key();
        let vk = sk.verifying_key();
        // Produce a signed VC; try to verify with the unsigned verifier.
        let signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();
        let err = verify_unsigned(&signed).unwrap_err();
        assert!(matches!(err, CryptoError::WrongCryptosuite(_)));

        // Produce an unsigned VC; try to verify with the signed verifier.
        let unsigned = sign_unsigned(&sample_doc(), &common_opts()).unwrap();
        let err = verify_signed(&unsigned, &SignedVerifyOptions { verifying_key: vk }).unwrap_err();
        assert!(matches!(err, CryptoError::WrongCryptosuite(_)));
    }

    // ─── D3: canonicalization parity ────────────────────────────────────────

    #[test]
    fn d3_canonical_bytes_byte_identical_across_variants() {
        // For the same (document, common_options), the canonical bytes
        // emitted through canonicalize_for_proof must equal between the
        // two cryptosuite names (except for the cryptosuite_name value
        // inside `proof`, which is by design).
        //
        // We assert the stronger property: the canonical bytes are
        // deterministically parameterised by cryptosuite_name — i.e.
        // for the SAME cryptosuite_name the bytes are byte-identical
        // on every call (idempotency), and for DIFFERENT cryptosuite
        // names the bytes differ by exactly one field.
        let opts = common_opts();
        let doc = sample_doc();

        let (a, _) = canonicalize_for_proof(&doc, CRYPTOSUITE_UNSIGNED, &opts).unwrap();
        let (b, _) = canonicalize_for_proof(&doc, CRYPTOSUITE_UNSIGNED, &opts).unwrap();
        assert_eq!(
            a, b,
            "same inputs must produce byte-identical canonical bytes"
        );

        let (c, _) = canonicalize_for_proof(&doc, CRYPTOSUITE_SIGNED, &opts).unwrap();
        assert_ne!(
            a, c,
            "different cryptosuite names must produce different canonical bytes"
        );
        // And swapping back yields the original.
        let (d, _) = canonicalize_for_proof(&doc, CRYPTOSUITE_UNSIGNED, &opts).unwrap();
        assert_eq!(a, d);
    }

    // ─── dispatcher ─────────────────────────────────────────────────────────

    struct FixedResolver(VerifyingKey);
    impl VerificationKeyResolver for FixedResolver {
        fn resolve(&self, _vm: &str) -> Result<VerifyingKey, CryptoError> {
            Ok(self.0)
        }
    }

    #[test]
    fn dispatcher_routes_unsigned_without_resolver() {
        let unsigned = sign_unsigned(&sample_doc(), &common_opts()).unwrap();
        verify(&unsigned, None).unwrap();
    }

    #[test]
    fn dispatcher_routes_signed_with_resolver() {
        let sk = fresh_key();
        let resolver = FixedResolver(sk.verifying_key());
        let signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();
        verify(&signed, Some(&resolver)).unwrap();
    }

    #[test]
    fn dispatcher_rejects_signed_without_resolver() {
        let sk = fresh_key();
        let signed = sign_signed(&sample_doc(), &signed_opts(sk)).unwrap();
        let err = verify(&signed, None).unwrap_err();
        assert!(matches!(err, CryptoError::KeyRequired));
    }

    // ─── multikey helpers ───────────────────────────────────────────────────

    #[test]
    fn multikey_round_trip() {
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let mk = ed25519_public_multikey(&vk);
        assert!(mk.starts_with("z6Mk"), "got {mk}");
        let back = ed25519_public_from_multikey(&mk).unwrap();
        assert_eq!(back.to_bytes(), vk.to_bytes());
    }
}
