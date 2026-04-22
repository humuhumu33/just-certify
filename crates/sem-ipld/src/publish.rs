//! The publish composition.
//!
//! # v0.2.1 revision — literal Babel Fish (post-review)
//!
//! An adversarial review of v0.2.0 correctly flagged that the original
//! design entangled the data block with the context reference:
//!
//! ```text
//! data block (v0.2.0):  { contextCid, contextIri, payload }
//! ```
//!
//! which meant `data_cid` was a function of `(payload, context)`, not
//! payload alone — so the "same payload → same fingerprint across
//! ecosystems" claim (C1) was only conditionally true. The revision
//! moves context into the certificate block:
//!
//! ```text
//! data block (v0.2.1):  <canonical payload bytes>                             (codec: dag-cbor OR raw)
//! cert block (v0.2.1):  { context, contextIri, data, fingerprint,
//!                         unitAddress, wittBits, wittLevelBits }               (codec: dag-cbor)
//! ```
//!
//! Now `data_cid` is a pure function of the canonical payload bytes.
//! C1 holds unconditionally: any two systems that compute
//! `dag_cbor_cid(dag_cbor_encode(payload))` (structured) or
//! `cid_from_sha256(raw, sha256(bytes))` (unstructured) see the same
//! `data_cid`, regardless of which context or UOR state they publish
//! against.
//!
//! # Security scope — what the blocks do *not* prove
//!
//! The certificate block is **not** self-signed. The CBOR fields
//! (`fingerprint`, `unitAddress`, `wittBits`, `wittLevelBits`) are
//! recoverable pointers that a consumer uses to locate, cache, and
//! index the grounded witness — **not** cryptographic claims. To
//! trust those fields, the consumer must re-run
//! `uor_foundation::pipeline::run_*` on the data block and verify
//! the resulting `Grounded<T>`'s accessors match. An adversary with
//! write access to the cert block can fabricate arbitrary witt bits
//! pointing at any data CID; sem-ipld's composition never claims
//! otherwise.
//!
//! The `integrity_attr` is a SHA-256 over **`data_bytes`** (the
//! canonical encoding a consumer will fetch from an IPFS gateway or
//! a content-addressed store) — not over the original serde value
//! the caller passed in. If you want integrity of a non-CBOR
//! serialization (e.g. raw JSON served by an HTTP endpoint), compute
//! it separately with [`crate::integrity::sha256_integrity_attribute`].

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use cid::Cid;
use serde::Serialize;
use uor_foundation::enforcement::{ContentFingerprint, Grounded, GroundedShape};

use crate::context::SemanticContext;
use crate::hasher::{CODEC_DAG_CBOR, CODEC_RAW};
use crate::integrity::Integrity;
use crate::ipld::{cid_from_sha256, encode};
use crate::Result;
use alloc::borrow::Cow;

/// The published block pair plus the browser-side integrity attribute.
///
/// # Integrity scope
///
/// [`Self::integrity_attr`] is SHA-256 over [`Self::data_bytes`]
/// (the canonical DAG-CBOR / raw encoding). It matches what an IPFS
/// gateway or a content-addressed store serves for the CID. If the
/// client fetches a different serialization (e.g. raw JSON served by
/// an HTTP endpoint), the client must compute integrity separately.
///
/// # Certificate authenticity scope
///
/// The cert block's fields are **not self-signed**. A consumer that
/// grants elevated trust based on `wittBits`, `wittLevelBits`, or
/// `fingerprint` must re-admit the data block through
/// `uor_foundation::pipeline::run_*` and check the resulting
/// `Grounded<T>::certificate()` matches the expected values.
#[derive(Debug, Clone)]
pub struct SemanticBlock {
    /// Canonical encoding of the payload alone — DAG-CBOR for
    /// structured payloads, the bytes themselves for opaque blobs.
    /// The `data_cid` is `CIDv1(<codec>, sha2-256, sha256(data_bytes))`.
    pub data_bytes: Vec<u8>,
    /// CID v1 of [`Self::data_bytes`]. Pure function of the payload.
    pub data_cid: Cid,
    /// DAG-CBOR of the certificate envelope — `{ context, contextIri,
    /// data, fingerprint, unitAddress, wittBits, wittLevelBits }`.
    pub certificate_bytes: Vec<u8>,
    /// CID v1 of [`Self::certificate_bytes`].
    pub certificate_cid: Cid,
    /// SRI-2 `sha256-…` value for `<link integrity="…">` over
    /// [`Self::data_bytes`] specifically. Consider using
    /// [`Self::integrity`] instead — it carries the IPIP-402 gateway
    /// contract alongside the string so URL construction cannot
    /// accidentally drop the `?format=raw` requirement.
    pub integrity_attr: String,

    /// Structured integrity attribute. Same SHA-256 as
    /// [`Self::integrity_attr`], but carries the `Accept` / `?format=`
    /// requirements for IPFS gateway fetches. Prefer this over the
    /// bare string.
    pub integrity: Integrity,
}

impl SemanticBlock {
    /// Build an IPFS gateway URL that returns the exact bytes
    /// [`Self::integrity`] verifies against — i.e., with
    /// `?format=raw` already appended.
    #[must_use]
    pub fn gateway_url(&self, gateway_base: &str) -> String {
        self.integrity.gateway_url(gateway_base, &self.data_cid)
    }
}

/// Publish a `Grounded<T, Tag>` as the IPLD block pair.
///
/// Data block: canonical DAG-CBOR of `domain_payload` alone.
/// Cert block: context + UOR metadata + back-link to data_cid.
///
/// # Errors
///
/// See [`crate::Error`].
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn publish_semantic<T, Tag, P>(
    grounded: &Grounded<T, Tag>,
    context: &SemanticContext,
    domain_payload: P,
) -> Result<SemanticBlock>
where
    T: GroundedShape,
    P: Serialize,
{
    publish_parts(
        context,
        &domain_payload,
        grounded.certificate().inner().witt_bits(),
        grounded.witt_level_bits(),
        grounded.unit_address().as_u128(),
        grounded.content_fingerprint(),
    )
}

/// Lower-level entry point taking raw UOR primitives.
///
/// `unit_address` is accepted as a full `u128` — the kernel's
/// `ContentAddress::as_u128()` width — and encoded as a 16-byte
/// big-endian byte string in the cert block. No silent truncation.
///
/// # Errors
///
/// See [`crate::Error`].
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn publish_parts<P>(
    context: &SemanticContext,
    domain_payload: &P,
    witt_bits: u16,
    witt_level_bits: u16,
    unit_address: u128,
    fingerprint: ContentFingerprint,
) -> Result<SemanticBlock>
where
    P: Serialize,
{
    // Data block = canonical DAG-CBOR of the payload alone.
    let (data_bytes, data_cid) = encode(domain_payload)?;
    finish(
        context,
        data_bytes,
        data_cid,
        witt_bits,
        witt_level_bits,
        unit_address,
        fingerprint,
    )
}

/// Publish **opaque bytes** (PDF, image, audio, model weights, tar, …).
/// The data block's codec is `raw` (0x55), not dag-cbor — the bytes
/// are the content itself, with no serialization wrapper.
///
/// # Errors
///
/// See [`crate::Error`].
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn publish_raw(
    context: &SemanticContext,
    raw_bytes: &[u8],
    witt_bits: u16,
    witt_level_bits: u16,
    unit_address: u128,
    fingerprint: ContentFingerprint,
) -> Result<SemanticBlock> {
    let data_bytes = raw_bytes.to_vec();
    let data_cid = cid_from_sha256(CODEC_RAW, &crate::hasher::sha256(raw_bytes))?;
    finish(
        context,
        data_bytes,
        data_cid,
        witt_bits,
        witt_level_bits,
        unit_address,
        fingerprint,
    )
}

#[cfg(feature = "serde")]
fn finish(
    context: &SemanticContext,
    data_bytes: Vec<u8>,
    data_cid: Cid,
    witt_bits: u16,
    witt_level_bits: u16,
    unit_address: u128,
    fingerprint: ContentFingerprint,
) -> Result<SemanticBlock> {
    let fp_width = fingerprint.width_bytes() as usize;
    let mut fp_buf = vec![0u8; fp_width];
    fp_buf.copy_from_slice(&fingerprint.as_bytes()[..fp_width]);

    // Full 128-bit unit address, big-endian. No silent truncation.
    let unit_address_be = unit_address.to_be_bytes();

    let (certificate_bytes, certificate_cid) = encode(&CertificateBlock {
        context: context.cid,
        context_iri: context.iri,
        data: data_cid,
        fingerprint: fp_buf,
        foundation_version: crate::REQUIRED_UOR_FOUNDATION_VERSION,
        unit_address: unit_address_be,
        witt_bits,
        witt_level_bits,
    })?;

    let integrity = Integrity::over(&data_bytes);
    Ok(SemanticBlock {
        integrity_attr: integrity.sri.clone(),
        integrity,
        data_bytes,
        data_cid,
        certificate_bytes,
        certificate_cid,
    })
}

// ─── Publishable trait — one call, any payload ──────────────────────────────
//
// Callers that don't want to choose between `publish_parts` (structured)
// and `publish_raw` (opaque) can use `publish()` with anything that
// implements `Publishable`. Blanket-impl'd for `&T: Serialize`; the
// `Raw` newtype is how you opt into the opaque-bytes / codec-raw path.

/// Newtype for opaque bytes. Wrap a byte slice in `Raw(&bytes)` to
/// tell [`publish`] to skip DAG-CBOR encoding and use the IPLD
/// `raw` codec instead — appropriate for PDFs, images, audio, model
/// weights, and any other content whose canonical form is the byte
/// sequence itself.
pub struct Raw<'a>(pub &'a [u8]);

/// Anything that knows how to produce its own canonical bytes and
/// name its IPLD codec. Feeds [`publish`].
///
/// The crate ships two impls:
/// * `impl<T: Serialize> Publishable for &T` — canonical DAG-CBOR via
///   [`crate::ipld::encode`], codec = `dag-cbor`.
/// * `impl Publishable for Raw<'_>` — the bytes as-is, codec = `raw`.
///
/// Downstream crates may provide additional impls (e.g. for an RDF
/// graph: URDNA2015-canonicalized N-Quads bytes with codec = `raw`).
pub trait Publishable {
    /// The canonical byte sequence that will be hashed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::EncodeFailed`] if the upstream
    /// encoder refuses the value.
    fn canonical_bytes(&self) -> Result<Cow<'_, [u8]>>;

    /// The IPLD multicodec for the resulting block.
    fn codec(&self) -> u64;
}

impl<T: Serialize + ?Sized> Publishable for &T {
    fn canonical_bytes(&self) -> Result<Cow<'_, [u8]>> {
        let v = serde_ipld_dagcbor::to_vec(*self).map_err(|_| crate::Error::EncodeFailed)?;
        Ok(Cow::Owned(v))
    }
    fn codec(&self) -> u64 {
        CODEC_DAG_CBOR
    }
}

impl Publishable for Raw<'_> {
    fn canonical_bytes(&self) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.0))
    }
    fn codec(&self) -> u64 {
        CODEC_RAW
    }
}

/// Single unified entry point. Feed it any [`Publishable`] — a
/// serde-serializable value (goes through DAG-CBOR) or a [`Raw`]
/// wrapper around opaque bytes (goes through the IPLD `raw` codec).
/// One mental model for all data types. Internally delegates to
/// [`publish_parts`] or the raw equivalent.
///
/// # Errors
///
/// See [`crate::Error`].
#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub fn publish<P: Publishable>(
    context: &SemanticContext,
    payload: P,
    witt_bits: u16,
    witt_level_bits: u16,
    unit_address: u128,
    fingerprint: ContentFingerprint,
) -> Result<SemanticBlock> {
    let bytes = payload.canonical_bytes()?;
    let codec = payload.codec();
    let data_cid = cid_from_sha256(codec, &crate::hasher::sha256(&bytes))?;
    finish(
        context,
        bytes.into_owned(),
        data_cid,
        witt_bits,
        witt_level_bits,
        unit_address,
        fingerprint,
    )
}

// ─── the cert block schema ──────────────────────────────────────────────────
//
// Keys emitted in lexicographic order — serde_ipld_dagcbor sorts for us,
// but we also declare fields in sorted order for readability.

#[derive(Serialize)]
struct CertificateBlock<'a> {
    /// IPLD link to the UOR OWL ontology context.
    context: Cid,
    /// Canonical IRI of the ontology (redundant with `context`, kept
    /// for human readers and for tools that don't resolve CIDs).
    #[serde(rename = "contextIri")]
    context_iri: &'a str,
    /// IPLD link back to the data block.
    data: Cid,
    /// UOR content fingerprint bytes (width-trimmed).
    #[serde(with = "serde_bytes")]
    fingerprint: Vec<u8>,
    /// Semver string of the `uor-foundation` release the admission
    /// was performed under. This is the missing pin in the
    /// content-addressed provenance story: `context` pins the
    /// ontology, `foundationVersion` pins the verifier.
    ///
    /// A re-verifier in the future that holds a `certificate_bytes`
    /// block knows *exactly* which kernel build to rehydrate in order
    /// to re-run `pipeline::run_*`. Without this field, a consumer
    /// could fetch the right ontology CID but run it through an
    /// incompatible kernel version and silently produce wrong
    /// verifications.
    #[serde(rename = "foundationVersion")]
    foundation_version: &'a str,
    /// Full 128-bit unit address, big-endian. 16 bytes — no truncation.
    #[serde(rename = "unitAddress", with = "serde_bytes_array")]
    unit_address: [u8; 16],
    /// Witt bits from the `GroundingCertificate`.
    #[serde(rename = "wittBits")]
    witt_bits: u16,
    /// Witt-level bits from `Grounded<T>`.
    #[serde(rename = "wittLevelBits")]
    witt_level_bits: u16,
}

// Adapter so serde_bytes treats a fixed-size array as a byte string.
mod serde_bytes_array {
    use serde::{Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes).serialize(s)
    }
}
