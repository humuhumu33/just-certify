//! Test vectors for the `uor-dag-cbor-2025` cryptosuite spec.
//!
//! These vectors are referenced verbatim by the spec document at
//! `sem-ipld-service/docs/specs/uor-dag-cbor-2025.md`. If any of the
//! expected values change, update both this test and the spec in lockstep.

use serde_json::json;
use uor_vc_crypto::{sign_unsigned, CommonOptions};

fn fixed_opts() -> CommonOptions {
    CommonOptions {
        verification_method: "did:web:uor.foundation#key-1".into(),
        proof_purpose: "assertionMethod".into(),
        created: Some("2026-04-22T00:00:00Z".into()),
    }
}

#[test]
fn vector_1_minimal_vc() {
    let doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": "VerifiableCredential",
        "credentialSubject": { "id": "urn:example:a" }
    });
    let signed = sign_unsigned(&doc, &fixed_opts()).unwrap();
    let proof_value = signed["proof"]["proofValue"].as_str().unwrap();
    // Pin the exact CID string — if this assertion fails, the spec's
    // Vector 1 must be updated to match.
    assert_eq!(
        proof_value,
        "bafyreidrgpukamm2nzybceezftonbye6j2itciwafmnaaqtmzhaecg3etq"
    );
}

#[test]
fn vector_2_nested_credential_subject() {
    let doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "ExampleCredential"],
        "credentialSubject": {
            "id": "urn:example:nested",
            "claims": { "age": 42, "wittBits": 8 }
        }
    });
    let signed = sign_unsigned(&doc, &fixed_opts()).unwrap();
    assert_eq!(
        signed["proof"]["proofValue"].as_str().unwrap(),
        "bafyreidrxhlfi5qbvbu5jm7ltp6evg3audsl7g2mzf4syxb2jduoob6jbq"
    );
}

#[test]
fn vector_3_array_of_subjects() {
    let doc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": "VerifiableCredential",
        "credentialSubject": [
            { "id": "urn:example:a", "k": 1 },
            { "id": "urn:example:b", "k": 2 }
        ]
    });
    let signed = sign_unsigned(&doc, &fixed_opts()).unwrap();
    assert_eq!(
        signed["proof"]["proofValue"].as_str().unwrap(),
        "bafyreicc54pbqv3p4hl7js6tj6zv6jf2efmsaw7wuuoupjr25dwget42xi"
    );
}
