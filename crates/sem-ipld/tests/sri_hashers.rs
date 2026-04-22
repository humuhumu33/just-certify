//! SHA-256 conformance tests. v0.2.0 ships only SHA-256 at the core;
//! wider SRI digests are an orthogonal ~20-LOC adapter per the
//! micro-kernel philosophy.

use sem_ipld::hasher::{sha256, SriHasher256};
use uor_foundation::enforcement::{Hasher as UorHasher, FINGERPRINT_MAX_BYTES};

// NIST FIPS 180-4 vectors.
const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

#[test]
fn sha256_empty() {
    assert_eq!(sha256(&[]), EMPTY_SHA256);
}

#[test]
fn sha256_abc() {
    assert_eq!(sha256(b"abc"), ABC_SHA256);
}

#[test]
fn uor_hasher_impl_matches_sha256() {
    let h = <SriHasher256 as UorHasher>::initial();
    let h = <SriHasher256 as UorHasher>::fold_bytes(h, b"abc");
    let out = <SriHasher256 as UorHasher>::finalize(h);
    assert_eq!(&out[..32], &ABC_SHA256[..]);
    // Bytes beyond OUTPUT_BYTES must be zero.
    assert_eq!(&out[32..], &[0u8; FINGERPRINT_MAX_BYTES - 32][..]);
}

#[test]
fn byte_by_byte_matches_bulk() {
    let input = b"The quick brown fox jumps over the lazy dog";
    let mut bb = SriHasher256::new();
    for &b in input {
        bb = <SriHasher256 as UorHasher>::fold_byte(bb, b);
    }
    assert_eq!(bb.finalize_32(), sha256(input));
}
