//! v0.3.0 W3C projection layer.
//!
//! * [`certificate_block_as_jsonld`] — render a decoded cert block as
//!   a JSON-LD document with `uor:*` terms and multibase-encoded
//!   byte fields.
//! * [`certificate_block_as_vc`] — build a VC 2.0 credential around
//!   that JSON-LD view, sign it with the `uor-dag-cbor-2025`
//!   cryptosuite, and return the secured document.
//!
//! Only the cert block (not the data block) projects into these
//! shapes. Callers asking for the data block as `?as=jsonld` or
//! `?as=vc` receive HTTP 406 via [`ProjectionRejection::NotACertBlock`].

use cid::Cid;
use serde::Deserialize;
use serde_json::{json, Value};
use uor_vc_crypto::{
    sign_signed as vc_sign_signed, sign_unsigned as vc_sign_unsigned, CommonOptions,
    SignedProofOptions,
};

use crate::multibase_util::encode_base58btc;
use crate::SigningConfig;

/// Issuer DID for every VC this service emits. Resolves via
/// `https://uor.foundation/.well-known/did.json` — see `docs/did/did.json`.
pub const ISSUER_DID: &str = "did:web:uor.foundation";

/// Verification-method URL embedded in every VC proof block.
pub const VERIFICATION_METHOD: &str = "did:web:uor.foundation#key-1";

/// The eight-field cert block shape — a serde view over the raw
/// DAG-CBOR bytes. Field renames match the on-wire keys; field
/// *Rust* names just happen to be snake_case for readability.
#[derive(Debug, Deserialize)]
pub struct CertBlockView {
    /// `context` — CID link to the UOR ontology document.
    pub context: Cid,
    /// `contextIri` — canonical IRI (redundant with `context`).
    #[serde(rename = "contextIri")]
    pub context_iri: String,
    /// `data` — CID link to the structural data block.
    pub data: Cid,
    /// `fingerprint` — UOR content fingerprint bytes (≤ 32).
    #[serde(with = "serde_bytes")]
    pub fingerprint: Vec<u8>,
    /// `foundationVersion` — `uor-foundation` version string.
    #[serde(rename = "foundationVersion")]
    pub foundation_version: String,
    /// `unitAddress` — 16-byte big-endian u128.
    #[serde(rename = "unitAddress", with = "serde_bytes")]
    pub unit_address: Vec<u8>,
    /// `wittBits` — from the grounding certificate.
    #[serde(rename = "wittBits")]
    pub witt_bits: u16,
    /// `wittLevelBits` — Grounded<T>::witt_level_bits.
    #[serde(rename = "wittLevelBits")]
    pub witt_level_bits: u16,
}

impl CertBlockView {
    /// Decode a cert block from its DAG-CBOR bytes. Returns `None` if
    /// the bytes do not have the exact eight-field cert-block shape —
    /// the signal the projection handlers use to return HTTP 406.
    #[must_use]
    pub fn try_decode(bytes: &[u8]) -> Option<Self> {
        serde_ipld_dagcbor::from_slice(bytes).ok()
    }

    /// The cert CID the caller asked for — used as the `@id` /
    /// `credentialSubject.id`-neighbouring reference.
    #[must_use]
    pub fn cert_cid_uri(cert_cid: &Cid) -> String {
        format!("ipfs://{cert_cid}")
    }
}

// ─── JSON-LD projection (TASK 4) ────────────────────────────────────────────

/// Render a cert block as a JSON-LD document. No proof attached — the
/// document is a declarative description, not a VC.
#[must_use]
pub fn certificate_block_as_jsonld(cert: &CertBlockView, cert_cid: &Cid) -> Value {
    json!({
        "@context": [
            "https://uor.foundation/",
            { "uor": "https://uor.foundation/" }
        ],
        "@id":   format!("ipfs://{cert_cid}"),
        "@type": "uor:GroundingCertificate",
        "uor:data":              { "@id": format!("ipfs://{}", cert.data) },
        "uor:context":           { "@id": format!("ipfs://{}", cert.context) },
        "uor:contextIri":        cert.context_iri,
        "uor:foundationVersion": cert.foundation_version,
        "uor:fingerprint":       encode_base58btc(&cert.fingerprint),
        "uor:unitAddress":       encode_base58btc(&cert.unit_address),
        "uor:wittBits":          cert.witt_bits,
        "uor:wittLevelBits":     cert.witt_level_bits,
    })
}

// ─── VC 2.0 projection (TASK 5) ─────────────────────────────────────────────

/// Render a cert block as a signed VC 2.0 credential using the
/// `uor-dag-cbor-2025` cryptosuite. On success, the returned value is
/// a secured VC with `proof.proofValue` set to the multibase-base32
/// CID of the credential's canonical form (minus `proofValue`).
///
/// # Errors
///
/// Returns [`uor_vc_crypto::CryptoError`] if the cryptosuite fails —
/// only reachable on canonicalization errors, which should never fire
/// for a well-formed cert view.
pub fn certificate_block_as_vc(
    cert: &CertBlockView,
    cert_cid: &Cid,
    signing: Option<&SigningConfig>,
) -> Result<Value, uor_vc_crypto::CryptoError> {
    let unsecured = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://uor.foundation/",
            { "uor": "https://uor.foundation/" }
        ],
        "type":      ["VerifiableCredential", "uor:GroundingCredential"],
        "id":        format!("ipfs://{cert_cid}"),
        "issuer":    ISSUER_DID,
        "validFrom": uor_vc_crypto_created_now(),
        "credentialSubject": {
            "id":                    format!("ipfs://{}", cert.data),
            "uor:fingerprint":       encode_base58btc(&cert.fingerprint),
            "uor:unitAddress":       encode_base58btc(&cert.unit_address),
            "uor:wittBits":          cert.witt_bits,
            "uor:wittLevelBits":     cert.witt_level_bits,
            "uor:contextIri":        cert.context_iri,
            "uor:context":           { "@id": format!("ipfs://{}", cert.context) },
            "uor:foundationVersion": cert.foundation_version
        }
    });

    let common = CommonOptions {
        verification_method: VERIFICATION_METHOD.to_string(),
        proof_purpose: "assertionMethod".to_string(),
        created: None,
    };

    // v0.4.0 dispatch: signed when a key is configured, unsigned
    // otherwise. The cryptosuite name in the emitted VC's proof
    // tells the consumer which they got.
    match signing {
        Some(cfg) => vc_sign_signed(
            &unsecured,
            &SignedProofOptions {
                common,
                signing_key: cfg.signing_key.clone(),
            },
        ),
        None => vc_sign_unsigned(&unsecured, &common),
    }
}

/// Ping helper — the cryptosuite's `current_rfc3339_timestamp` is
/// private, so we reach for a local equivalent here to stamp the VC
/// `validFrom`. Matches the cryptosuite's format bit-for-bit
/// (same algorithm).
fn uor_vc_crypto_created_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock sane");
    let unix_secs = now.as_secs() as i64;
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
    let mth = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if mth <= 2 { y + 1 } else { y };
    format!("{year:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Marker for "cannot project this block into W3C form" — the shape
/// maps to HTTP 406 in the handler.
pub struct NotACertBlock;

/// Assert this byte sequence is decodable as a cert block. Returns
/// the decoded view or [`NotACertBlock`] to be mapped to HTTP 406.
///
/// # Errors
///
/// Returns [`NotACertBlock`] if the bytes do not decode as the
/// eight-field cert schema.
pub fn assert_cert_block(bytes: &[u8]) -> Result<CertBlockView, NotACertBlock> {
    CertBlockView::try_decode(bytes).ok_or(NotACertBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_vc_crypto::{verify as vc_verify, CRYPTOSUITE_NAME};

    fn sample_view() -> (CertBlockView, Cid) {
        let data_cid: Cid = "bafyreihltcnuuyqp2jm24aqydpnlj7b6w3ogwrplomrjtg5rifv44mmjey"
            .parse()
            .unwrap();
        let ctx_cid: Cid = "bafyreig2u5g3vjapucxortrdoouufsrk7nbbcu5p7elfmcfdxhhc6k3qzy"
            .parse()
            .unwrap();
        let cert_cid: Cid = "bafyreicti7eyzvx6lnabyfcwccm3talwgp4ogh4gqowpugtwd7so4gc2pi"
            .parse()
            .unwrap();
        let view = CertBlockView {
            context: ctx_cid,
            context_iri: "https://uor.foundation/".into(),
            data: data_cid,
            fingerprint: vec![0xabu8; 32],
            foundation_version: "0.3.0".into(),
            unit_address: vec![0u8; 16],
            witt_bits: 8,
            witt_level_bits: 8,
        };
        (view, cert_cid)
    }

    #[test]
    fn jsonld_projection_has_expected_keys() {
        let (view, cid) = sample_view();
        let j = certificate_block_as_jsonld(&view, &cid);
        assert_eq!(j["@type"], "uor:GroundingCertificate");
        assert_eq!(j["uor:wittBits"], 8);
        // Byte fields are multibase (z-prefix).
        let fp = j["uor:fingerprint"].as_str().unwrap();
        assert!(fp.starts_with('z'), "got {fp}");
        // CID fields are {"@id": "ipfs://…"} wrappers.
        assert_eq!(
            j["uor:data"]["@id"].as_str().unwrap(),
            "ipfs://bafyreihltcnuuyqp2jm24aqydpnlj7b6w3ogwrplomrjtg5rifv44mmjey"
        );
    }

    #[test]
    fn vc_projection_signs_and_round_trip_verifies() {
        let (view, cid) = sample_view();
        let vc = certificate_block_as_vc(&view, &cid, None).unwrap();

        // Required VC 2.0 fields.
        assert_eq!(vc["issuer"], ISSUER_DID);
        assert!(vc["@context"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "https://www.w3.org/ns/credentials/v2"));
        assert!(vc["type"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "VerifiableCredential"));

        // Proof shape.
        let proof_value = vc["proof"]["proofValue"].as_str().unwrap();
        assert!(proof_value.starts_with("bafyrei"), "got {proof_value}");
        assert_eq!(vc["proof"]["cryptosuite"], CRYPTOSUITE_NAME);

        // Round-trip via the cryptosuite verifier (unsigned).
        vc_verify(&vc, None).expect("freshly-signed VC must verify");
    }

    #[test]
    fn tampered_vc_fails_verification() {
        let (view, cid) = sample_view();
        let mut vc = certificate_block_as_vc(&view, &cid, None).unwrap();
        vc["credentialSubject"]["uor:wittBits"] = json!(99);
        let err = vc_verify(&vc, None).unwrap_err();
        assert!(
            matches!(err, uor_vc_crypto::CryptoError::ProofMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn non_cert_bytes_return_none() {
        // dag-cbor of `{"a": 1}` — not a cert block.
        let arbitrary = [0xa1u8, 0x61, 0x61, 0x01];
        assert!(CertBlockView::try_decode(&arbitrary).is_none());
    }
}
