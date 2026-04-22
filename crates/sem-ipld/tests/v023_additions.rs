//! Tests for the v0.2.3 additive surface:
//! * `Integrity` type + `SemanticBlock::gateway_url`
//! * `publish()` / `Publishable` / `Raw`
//! * `load()` / `Loaded`
//! * `REQUIRED_UOR_FOUNDATION_VERSION` drift lock

#![cfg(feature = "publish")]

use sem_ipld::prelude::*;
use serde_json::json;
use uor_foundation::enforcement::ContentFingerprint;

const CONTEXT: &[u8] = br#"{"@context":{"u":"https://uor.foundation/"}}"#;

fn ctx() -> SemanticContext {
    SemanticContext::with_bytes(SemanticContext::CANONICAL_IRI, CONTEXT).unwrap()
}

// ─── #3: Integrity type ─────────────────────────────────────────────────────

#[test]
fn integrity_type_carries_transport_contract() {
    // Constants are the IPIP-402 values a gateway needs.
    assert_eq!(Integrity::REQUIRED_ACCEPT, "application/vnd.ipld.raw");
    assert_eq!(Integrity::REQUIRED_FORMAT_PARAM, "raw");

    let i = Integrity::over(b"hello");
    assert!(i.sri.starts_with("sha256-"));
}

#[test]
fn gateway_url_bakes_in_raw_format() {
    let block = publish_parts(
        &ctx(),
        &json!({ "v": 1 }),
        1,
        1,
        0,
        ContentFingerprint::from_buffer([0u8; 32], 32),
    )
    .unwrap();

    let url = block.gateway_url("https://ipfs.io");
    assert!(url.starts_with("https://ipfs.io/ipfs/bafyrei"));
    assert!(url.ends_with("?format=raw"));
}

#[test]
fn block_integrity_field_and_attr_agree() {
    let block = publish_parts(
        &ctx(),
        &json!({ "v": 1 }),
        1,
        1,
        0,
        ContentFingerprint::from_buffer([0u8; 32], 32),
    )
    .unwrap();
    assert_eq!(block.integrity.sri, block.integrity_attr);
}

// ─── #1: Publishable trait + publish() ──────────────────────────────────────

#[test]
fn publish_via_trait_structured_matches_publish_parts() {
    let payload = json!({ "foaf:name": "Ada" });
    let fp = ContentFingerprint::from_buffer([0u8; 32], 32);

    let via_trait = publish(&ctx(), &payload, 1, 1, 0, fp).unwrap();
    let via_parts = publish_parts(&ctx(), &payload, 1, 1, 0, fp).unwrap();

    assert_eq!(via_trait.data_cid, via_parts.data_cid);
    assert_eq!(via_trait.certificate_cid, via_parts.certificate_cid);
    assert_eq!(via_trait.data_bytes, via_parts.data_bytes);
}

#[test]
fn publish_via_trait_raw_matches_publish_raw() {
    let pdf = b"%PDF-1.7 sample";
    let fp = ContentFingerprint::from_buffer(sem_ipld::hasher::sha256(pdf), 32);

    let via_trait = publish(&ctx(), Raw(pdf), 1, 1, 0, fp).unwrap();
    let via_raw = publish_raw(&ctx(), pdf, 1, 1, 0, fp).unwrap();

    assert_eq!(via_trait.data_cid, via_raw.data_cid);
    assert_eq!(via_trait.data_bytes, via_raw.data_bytes);
}

// ─── #4: load() with Loaded enum ────────────────────────────────────────────

#[test]
fn load_classifies_sem_ipld_envelope() {
    let ctx = ctx();
    let native = json!({
        "@context": [ctx.iri, { "u": ctx.iri }],
        "@type": "u:Grounded",
        "u:contextCid": ctx.cid.to_string(),
        "u:payload": { "v": 1 },
    });
    match load(&native) {
        Loaded::SemIpld(_) => {}
        other => panic!("expected SemIpld, got {other:?}"),
    }
}

#[test]
fn load_classifies_pass_through() {
    let doc = json!({ "@context": "https://uor.foundation/", "foaf:name": "Dana" });
    match load(&doc) {
        Loaded::PassThrough(_) => {}
        other => panic!("expected PassThrough, got {other:?}"),
    }
}

#[test]
fn load_classifies_not_json_ld() {
    match load(&json!("string")) {
        Loaded::NotJsonLd => {}
        other => panic!("expected NotJsonLd, got {other:?}"),
    }
    // Object with no @context is also not JSON-LD here.
    match load(&json!({ "foo": "bar" })) {
        Loaded::NotJsonLd => {}
        other => panic!("expected NotJsonLd for no-@context object, got {other:?}"),
    }
}

// ─── #5: REQUIRED_UOR_FOUNDATION_VERSION must match Cargo.toml ──────────────

/// If this test fails, the const has drifted from the actual `uor-foundation`
/// dependency version. Update the const in `src/lib.rs` when bumping the
/// foundation dep.
#[test]
fn required_uor_foundation_version_matches_cargo_toml() {
    let manifest = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Cargo.toml"
    ))
    .expect("read Cargo.toml");

    // Find the version pinned on `uor-foundation = { version = "x.y.z", ...`
    let Some(line) = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("uor-foundation ="))
    else {
        panic!("uor-foundation dependency line not found in Cargo.toml");
    };
    // Extract the version string between the first pair of double quotes.
    let version = line
        .split('"')
        .nth(1)
        .expect("uor-foundation version quoted string");
    assert_eq!(
        sem_ipld::REQUIRED_UOR_FOUNDATION_VERSION, version,
        "REQUIRED_UOR_FOUNDATION_VERSION const drifted from Cargo.toml dep"
    );
}
