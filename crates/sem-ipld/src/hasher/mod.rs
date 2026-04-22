//! The one adapter the whole overlay turns on: `SriHasher256`.
//!
//! This is the minimal-surface realisation of the "low proposal":
//! **a single `impl uor_foundation::Hasher`** that uses SHA-256 from
//! RustCrypto, and which also serves as the hash function for CID
//! multihashes (same bytes, two audiences).
//!
//! SHA-384 / SHA-512 are **not implemented** in v0.2.0. The rationale:
//!
//! * The UOR fingerprint envelope is 32 bytes (`FINGERPRINT_MAX_BYTES`),
//!   so only SHA-256 can be the inner UOR hash.
//! * For the outer SRI / CID layer, SHA-256 is by far the most common
//!   choice (it is the IPFS default and an SRI-2 first-tier algorithm).
//! * Any caller who needs a wider outer digest writes their own 20-LOC
//!   adapter in their own crate — the low proposal's whole point.

use sha2::{Digest, Sha256};
use uor_foundation::enforcement::{Hasher as UorHasher, FINGERPRINT_MAX_BYTES};

/// SRI-2 SHA-256 hasher. Serves two roles:
///
/// * Inner UOR fingerprint via `uor_foundation::Hasher`.
/// * Outer SRI / CID multihash via the free function [`sha256`].
#[derive(Clone, Default)]
pub struct SriHasher256(Sha256);

impl SriHasher256 {
    /// Fresh state.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Absorb a byte slice.
    #[must_use]
    pub fn update(mut self, bytes: &[u8]) -> Self {
        self.0.update(bytes);
        self
    }

    /// Finalize into a 32-byte SHA-256 digest.
    #[must_use]
    pub fn finalize_32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0.finalize());
        out
    }
}

impl UorHasher for SriHasher256 {
    const OUTPUT_BYTES: usize = 32;

    fn initial() -> Self {
        Self::new()
    }

    fn fold_byte(mut self, b: u8) -> Self {
        self.0.update([b]);
        self
    }

    fn fold_bytes(self, bytes: &[u8]) -> Self {
        self.update(bytes)
    }

    fn finalize(self) -> [u8; FINGERPRINT_MAX_BYTES] {
        let mut out = [0u8; FINGERPRINT_MAX_BYTES];
        out[..32].copy_from_slice(&self.finalize_32());
        out
    }
}

/// Plain free-function: SHA-256 of a byte slice.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    SriHasher256::new().update(bytes).finalize_32()
}

/// Multihash code for SHA-256.
pub const MULTIHASH_SHA2_256: u64 = 0x12;

/// Multicodec for DAG-CBOR.
pub const CODEC_DAG_CBOR: u64 = 0x71;

/// Multicodec for `raw` blocks (opaque bytes).
pub const CODEC_RAW: u64 = 0x55;
