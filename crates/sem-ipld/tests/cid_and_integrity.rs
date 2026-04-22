//! CID + SRI integrity tests via the upstream `cid` crate.

#![cfg(feature = "alloc")]

use sem_ipld::hasher::sha256;
use sem_ipld::integrity::sha256_integrity_attribute;
use sem_ipld::ipld::{cid_from_sha256, dag_cbor_cid};
use sem_ipld::prelude::*;

#[test]
fn dag_cbor_cid_matches_expected_codec_and_mh() {
    let cid = dag_cbor_cid(b"hello").unwrap();
    // CIDv1 dag-cbor sha2-256 text encoding starts with "bafyrei…" (base32).
    let s = cid.to_string();
    assert!(s.starts_with("bafyrei"), "got {s}");
    // Codec is dag-cbor.
    assert_eq!(cid.codec(), CODEC_DAG_CBOR);
    // Multihash code is SHA-256.
    assert_eq!(cid.hash().code(), MULTIHASH_SHA2_256);
    // Digest bytes match a direct SHA-256 of the input.
    assert_eq!(cid.hash().digest(), &sha256(b"hello"));
}

#[test]
fn raw_cid_uses_raw_codec() {
    let cid = cid_from_sha256(CODEC_RAW, &sha256(b"opaque bytes")).unwrap();
    assert_eq!(cid.codec(), CODEC_RAW);
}

#[test]
fn integrity_attribute_empty() {
    // SRI-2 sha256 over "" is: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    // standard base64 of those 32 bytes = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    assert_eq!(
        sha256_integrity_attribute(&[]),
        "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}

#[test]
fn integrity_attribute_format() {
    let attr = sha256_integrity_attribute(b"body");
    assert!(attr.starts_with("sha256-"));
    // "sha256-" (7) + base64(32 bytes) = 7 + 44 = 51.
    assert_eq!(attr.len(), 51);
}
