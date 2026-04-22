//! The IPLD adapter. This is the *heart* of the overlay — and it is
//! deliberately small because the heavy lifting (CID construction,
//! DAG-CBOR encoding, multihash framing) is delegated to the upstream
//! `cid` and `serde_ipld_dagcbor` crates.
//!
//! The adapter's job is narrow: given bytes, produce a CIDv1 over
//! dag-cbor + sha2-256. Given a serde-serializable value, produce the
//! deterministic DAG-CBOR encoding. That's it.

extern crate alloc;
use alloc::vec::Vec;

use cid::Cid;
use serde::Serialize;

use crate::hasher::{sha256, CODEC_DAG_CBOR, MULTIHASH_SHA2_256};

/// CIDv1 over a sha2-256 digest with the supplied codec.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidContextCid`] only if the upstream
/// `cid` crate rejects the multihash construction, which for a correct
/// 32-byte SHA-256 digest cannot happen.
pub fn cid_from_sha256(codec: u64, digest: &[u8; 32]) -> crate::Result<Cid> {
    use cid::multihash::Multihash;
    let mh = Multihash::<64>::wrap(MULTIHASH_SHA2_256, digest)
        .map_err(|_| crate::Error::InvalidContextCid)?;
    Ok(Cid::new_v1(codec, mh))
}

/// CIDv1(dag-cbor, sha2-256) of a byte slice.
///
/// # Errors
///
/// See [`cid_from_sha256`].
pub fn dag_cbor_cid(bytes: &[u8]) -> crate::Result<Cid> {
    cid_from_sha256(CODEC_DAG_CBOR, &sha256(bytes))
}

/// Encode a value as deterministic DAG-CBOR and return the bytes + CID.
///
/// # Errors
///
/// Returns [`crate::Error::EncodeFailed`] if the upstream encoder
/// refuses the value (non-serializable, non-deterministic, etc.).
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn encode<T: Serialize>(value: &T) -> crate::Result<(Vec<u8>, Cid)> {
    let bytes = serde_ipld_dagcbor::to_vec(value).map_err(|_| crate::Error::EncodeFailed)?;
    let cid = dag_cbor_cid(&bytes)?;
    Ok((bytes, cid))
}
