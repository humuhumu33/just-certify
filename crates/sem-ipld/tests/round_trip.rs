//! End-to-end round-trip: the structural-vs-proof split, the
//! bidirectional link, and the JSON-LD loader all exercised through
//! the public surface.

#![cfg(feature = "publish")]

use sem_ipld::hasher::sha256;
use sem_ipld::prelude::*;
use serde_json::json;
use uor_foundation::enforcement::ContentFingerprint;

const CONTEXT_BYTES: &[u8] = br#"{"@context":{"u":"https://uor.foundation/"}}"#;

fn ctx() -> SemanticContext {
    SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, CONTEXT_BYTES).unwrap()
}

/// Same payload → same `data_cid`, even when UOR state differs.
#[test]
fn data_cid_is_independent_of_uor_state() {
    let context = ctx();
    let payload = json!({ "u:knows": "Alice", "u:age": 30 });

    let block_a = publish_parts(
        &context,
        &payload,
        /* witt_bits       */ 7,
        /* witt_level_bits */ 3,
        /* unit_address    */ 0xaaaa,
        ContentFingerprint::from_buffer([1u8; 32], 32),
    )
    .unwrap();

    let block_b = publish_parts(
        &context,
        &payload,
        11,
        5,
        0xbbbb,
        ContentFingerprint::from_buffer([2u8; 32], 32),
    )
    .unwrap();

    assert_eq!(block_a.data_cid, block_b.data_cid);
    assert_ne!(block_a.certificate_cid, block_b.certificate_cid);
}

/// The certificate block's DAG-CBOR decodes back and the `data` field
/// equals `data_cid`.
#[test]
fn certificate_block_links_back_to_data_cid() {
    let context = ctx();
    let payload = json!({ "u:knows": "Bob" });

    let block = publish_parts(
        &context,
        &payload,
        7,
        3,
        0x1234,
        ContentFingerprint::from_buffer([0xab; 32], 32),
    )
    .unwrap();

    // Decode as the native IPLD enum so we can inspect the Link variant.
    use ipld_core::ipld::Ipld;
    let cert: Ipld = serde_ipld_dagcbor::from_slice(&block.certificate_bytes).unwrap();
    let Ipld::Map(map) = cert else {
        panic!("cert block is not a map");
    };
    match map.get("data") {
        Some(Ipld::Link(link)) => assert_eq!(link, &block.data_cid),
        other => panic!("cert `data` field is not a CID link: {other:?}"),
    }
}

/// `integrity_attr` matches the SHA-256 of `data_bytes`.
#[test]
fn integrity_attr_matches_data_sha256() {
    let context = ctx();
    let payload = json!({ "hello": "world" });
    let block = publish_parts(
        &context,
        &payload,
        1,
        1,
        1,
        ContentFingerprint::from_buffer([0u8; 32], 32),
    )
    .unwrap();

    // integrity is sha256 of data_bytes; and the CID's multihash digest is the same.
    assert_eq!(block.data_cid.hash().digest(), &sha256(&block.data_bytes));
    assert!(block.integrity_attr.starts_with("sha256-"));
}

/// load_as_jsonld round-trip: projection → load preserves context + payload.
#[test]
fn load_as_jsonld_round_trip() {
    let context = ctx();
    let payload = json!({ "u:knows": "Carol" });

    let projected = json!({
        "@context": [context.iri, { "u": context.iri }],
        "@type": "u:Grounded",
        "u:contextCid": context.cid.to_string(),
        "u:payload": payload.clone(),
    });

    let loaded = load_as_jsonld(&projected).unwrap();
    assert_eq!(loaded.context_iri, context.iri);
    assert_eq!(loaded.context_cid.as_deref(), Some(context.cid.to_string().as_str()));
    assert_eq!(loaded.payload, payload);
}

#[test]
fn load_as_jsonld_passthrough() {
    let doc = json!({
        "@context": "https://uor.foundation/",
        "foaf:name": "Dana",
    });
    let loaded = load_as_jsonld(&doc).unwrap();
    assert_eq!(loaded.context_iri, "https://uor.foundation/");
    assert!(loaded.context_cid.is_none());
    assert_eq!(loaded.payload, json!({ "foaf:name": "Dana" }));
}

#[test]
fn load_as_jsonld_rejects_non_object() {
    assert!(load_as_jsonld(&json!("string")).is_err());
}

/// `load_as_jsonld_strict` refuses any document that lacks the SemIPLD
/// envelope — the disambiguation the reviewer requested.
#[test]
fn load_as_jsonld_strict_rejects_pass_through() {
    use sem_ipld::jsonld::load_as_jsonld_strict;

    // Plain JSON-LD pass-through — lenient mode would accept this.
    let passthrough = json!({
        "@context": "https://uor.foundation/",
        "foaf:name": "Dana",
    });
    assert!(load_as_jsonld_strict(&passthrough).is_err());

    // Missing u:payload — still rejected even though the other fields exist.
    let incomplete = json!({
        "@context": "https://uor.foundation/",
        "u:contextCid": "bafyreib...",
    });
    assert!(load_as_jsonld_strict(&incomplete).is_err());

    // Full SemIPLD envelope — accepted.
    let context = ctx();
    let native = json!({
        "@context": [context.iri, { "u": context.iri }],
        "@type": "u:Grounded",
        "u:contextCid": context.cid.to_string(),
        "u:payload": { "v": 1 },
    });
    assert!(load_as_jsonld_strict(&native).is_ok());
}

/// `publish_raw` handles opaque byte blobs (PDF / image / audio / code)
/// exactly like `publish_parts` handles structured payloads — same CID
/// stability under UOR state changes, same integrity semantics.
#[test]
fn publish_raw_covers_opaque_blobs() {
    let context = ctx();
    let pdf = b"%PDF-1.7 sample body".as_slice();

    let block_a = publish_raw(
        &context,
        pdf,
        1,
        1,
        1,
        ContentFingerprint::from_buffer(sha256(pdf), 32),
    )
    .unwrap();
    let block_b = publish_raw(
        &context,
        pdf,
        99,
        99,
        99,
        ContentFingerprint::from_buffer([0xff; 32], 32),
    )
    .unwrap();

    // Same payload → same data CID, regardless of the UOR state.
    assert_eq!(block_a.data_cid, block_b.data_cid);
    // A different byte payload → different CID.
    let other = publish_raw(
        &context,
        b"different bytes",
        1,
        1,
        1,
        ContentFingerprint::from_buffer([0u8; 32], 32),
    )
    .unwrap();
    assert_ne!(block_a.data_cid, other.data_cid);
}

#[test]
fn context_cid_is_deterministic() {
    let a = SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, CONTEXT_BYTES).unwrap();
    let b = SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, CONTEXT_BYTES).unwrap();
    assert_eq!(a.cid, b.cid);
    let c = SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, b"other").unwrap();
    assert_ne!(a.cid, c.cid);
}
