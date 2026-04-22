//! Golden-CID regression tests.
//!
//! These freeze the canonical bytes and resulting CIDs for a fixed
//! set of payloads. If `serde_ipld_dagcbor` ever changes its
//! float-encoding, integer-form, or key-sort behavior in a minor
//! version bump, these tests fail immediately — a CI run before
//! publishing a new sem-ipld release will catch the drift before it
//! silently changes the wire format seen by downstream consumers.
//!
//! Mitigation layer for the reviewer's §4 operational concern
//! (`serde_ipld_dagcbor` version drift risk).

#![cfg(feature = "publish")]

use sem_ipld::prelude::*;
use serde_json::json;
use uor_foundation::enforcement::ContentFingerprint;

// ─── Structured payload ─────────────────────────────────────────────────────

/// Golden: the DAG-CBOR of `{"a": 1, "b": "hello"}` is known to
/// sort keys length-first (both 1 byte → byte-compare) and
/// produce `0xa2 61 61 01 61 62 65 68 65 6c 6c 6f`.
const GOLDEN_AB_CBOR: &[u8] = &[
    0xa2, // map(2)
    0x61, b'a', // "a"
    0x01, // 1
    0x61, b'b', // "b"
    0x65, b'h', b'e', b'l', b'l', b'o', // "hello"
];

#[test]
fn golden_structured_cbor_bytes() {
    let (bytes, _cid) = dag_cbor_encode(&json!({ "a": 1, "b": "hello" })).unwrap();
    assert_eq!(
        bytes, GOLDEN_AB_CBOR,
        "serde_ipld_dagcbor output drift — freeze the minor version"
    );
}

#[test]
fn golden_structured_cid_is_stable() {
    let (_, cid_a) = dag_cbor_encode(&json!({ "a": 1, "b": "hello" })).unwrap();
    // Keys given in reverse order — must still produce the same CID.
    let (_, cid_b) = dag_cbor_encode(&json!({ "b": "hello", "a": 1 })).unwrap();
    assert_eq!(cid_a, cid_b);

    let expected = cid_a.to_string();
    // Known-good CIDv1(dag-cbor, sha2-256) prefix.
    assert!(expected.starts_with("bafyrei"));
    // Pin exact text — any drift flips this string immediately.
    assert_eq!(
        expected,
        "bafyreifclfpajlxsvztnfu6m3dm4cg3pt5awis24ranobyuhde2co5vtxa"
    );
}

// ─── Unstructured payload ───────────────────────────────────────────────────

#[test]
fn golden_raw_cid_is_stable() {
    let bytes = b"sem-ipld-golden-raw";
    let context = SemanticContext::with_bytes(
        SemanticContext::CANONICAL_IRI,
        br#"{"@context":{"u":"https://uor.foundation/"}}"#,
    )
    .unwrap();
    let block = publish_raw(
        &context,
        bytes,
        1,
        1,
        0,
        ContentFingerprint::from_buffer(sha256(bytes), 32),
    )
    .unwrap();

    // The raw-bytes CID is `CIDv1(raw, sha2-256)` over `bytes`.
    // Raw-codec CIDs start with "bafkrei…" in multibase-b32.
    let s = block.data_cid.to_string();
    assert!(s.starts_with("bafkrei"), "raw CID prefix drift: {s}");
    // And it must match the CID recomputed independently.
    let independent = sem_ipld::ipld::cid_from_sha256(CODEC_RAW, &sha256(bytes)).unwrap();
    assert_eq!(block.data_cid, independent);
}

// ─── Certificate-block schema lock-in ───────────────────────────────────────

/// The cert block carries exactly eight fields after v0.2.2. If this
/// count changes, the test forces explicit review before a wire-
/// format change lands.
#[test]
fn cert_block_has_eight_fields() {
    let context = SemanticContext::with_bytes(
        SemanticContext::CANONICAL_IRI,
        br#"{"@context":{"u":"https://uor.foundation/"}}"#,
    )
    .unwrap();
    let block = publish_parts(
        &context,
        &json!({ "v": 1 }),
        1,
        1,
        0,
        ContentFingerprint::from_buffer([0u8; 32], 32),
    )
    .unwrap();

    use ipld_core::ipld::Ipld;
    let cert: Ipld = serde_ipld_dagcbor::from_slice(&block.certificate_bytes).unwrap();
    let Ipld::Map(m) = cert else {
        panic!("cert is not a map");
    };
    // context, contextIri, data, fingerprint, foundationVersion,
    // unitAddress, wittBits, wittLevelBits = 8.
    assert_eq!(m.len(), 8, "cert block field count changed — review wire format");
    assert!(m.contains_key("foundationVersion"));
    match m.get("foundationVersion") {
        Some(Ipld::String(s)) => assert!(!s.is_empty()),
        other => panic!("foundationVersion is not a string: {other:?}"),
    }
}
