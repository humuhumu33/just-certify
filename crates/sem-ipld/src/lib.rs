// sem-ipld — the surgical adapter between the UOR micro-kernel and the
// ambient web (IPLD, JSON-LD, SRI-2).
//
// © 2026 The UOR Foundation. Licensed under the Apache License, Version 2.0.
//
// ─────────────────────────────────────────────────────────────────────────────
// Philosophy (the "low proposal" north star)
// ─────────────────────────────────────────────────────────────────────────────
//
//   UOR changes nothing in any existing system. sem-ipld is the thin
//   convenience layer on top of a one-file IPLD adapter. Every concern
//   the upstream Rust ecosystem already solves well is delegated to
//   that upstream crate, not re-implemented here.
//
//   In v0.2.0 this meant deleting hand-rolled CID, DAG-CBOR, varint,
//   base32, and base64 modules (collectively ~700 LOC) in favour of
//   the `cid`, `serde_ipld_dagcbor`, and `base64` crates. What remains
//   is the composition itself — the part that genuinely belongs in
//   this overlay and nowhere else.
//
//   Foundation anchors (every citation is load-bearing):
//
//     * uor_foundation::Hasher            foundation/src/enforcement.rs:5966
//     * uor_foundation::Grounded<T, Tag>  foundation/src/enforcement.rs:7329
//     * uor_foundation::GroundingCertificate foundation/src/enforcement.rs:4374
//     * FINGERPRINT_MAX_BYTES (= 32)      foundation/src/enforcement.rs:5888
//
// ─────────────────────────────────────────────────────────────────────────────

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

//! # sem-ipld
//!
//! **Surgical adapter** between the UOR Foundation micro-kernel and the
//! ambient web: IPLD (decentralized identity), JSON-LD (ambient
//! semantics), and SRI-2 (browser-native verification).
//!
//! ```rust,ignore
//! use sem_ipld::prelude::*;
//!
//! let context = SemanticContext::with_bytes(
//!     SemanticContext::CANONICAL_IRI, UOR_CONTEXT_BYTES,
//! )?;
//!
//! let block = publish_semantic(&grounded, &context, payload_json)?;
//!
//! // block.data_cid          — CID v1 of the structural content
//! // block.certificate_cid   — CID v1 of the proof block (links back to data_cid)
//! // block.integrity_attr    — `sha256-…` string for <link integrity="…">
//! // block.data_bytes        — deterministic DAG-CBOR (for IPFS put)
//! // block.certificate_bytes — deterministic DAG-CBOR
//! ```
//!
//! ## Feature matrix
//!
//! | Feature   | Default | Surface it turns on |
//! |-----------|---------|---------------------|
//! | (none)    | on      | `#![no_std]`: `SriHasher256`, multihash/multicodec constants. |
//! | `alloc`   | off     | `cid`, `serde_ipld_dagcbor`, `base64` — the IPLD + integrity adapters. |
//! | `std`     | off     | std-only conveniences. Implies `alloc`. |
//! | `serde`   | off     | JSON-LD projection (`project_grounded`), `load_as_jsonld`, `publish_semantic`. Implies `alloc`. |
//! | `publish` | off     | Convenience union (`alloc + serde`). |

#[cfg(feature = "alloc")]
extern crate alloc;

// ─── the one kernel-facing trait anchor ──────────────────────────────────────
// (`#[path]` is used to disambiguate between `hasher.rs` and `hasher/mod.rs`
// in the sandbox filesystem — the stale `hasher.rs` file exists but cannot
// be deleted here. `hasher/mod.rs` is canonical.)

#[path = "hasher/mod.rs"]
pub mod hasher;

// ─── the three ecosystem adapters ────────────────────────────────────────────

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod ipld;

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod integrity;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod jsonld;

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod context;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod publish;

// ─── prelude ─────────────────────────────────────────────────────────────────

/// Convenience re-exports — the only `use` most callers will need.
pub mod prelude {
    pub use crate::hasher::{sha256, SriHasher256, CODEC_DAG_CBOR, CODEC_RAW, MULTIHASH_SHA2_256};

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub use crate::context::SemanticContext;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub use crate::integrity::{sha256_integrity_attribute, Integrity};

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub use crate::ipld::{cid_from_sha256, dag_cbor_cid};

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub use cid::Cid;

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    pub use crate::ipld::encode as dag_cbor_encode;

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    pub use crate::jsonld::{
        load, load_as_jsonld, load_as_jsonld_strict, project_grounded, Loaded,
        SemanticInput,
    };

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    pub use crate::publish::{
        publish, publish_parts, publish_raw, publish_semantic, Publishable, Raw,
        SemanticBlock,
    };

    // Foundation anchors.
    pub use uor_foundation::{
        ContentFingerprint, Grounded, GroundingCertificate, Hasher, Trace, TraceEvent,
    };
}

// ─── one error enum ──────────────────────────────────────────────────────────

/// Every fallible operation in sem-ipld returns `Result<T, Error>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The upstream `cid` crate rejected the multihash construction
    /// (impossible for a correct 32-byte SHA-256 digest).
    InvalidContextCid,

    /// The upstream DAG-CBOR encoder refused a value (e.g. a
    /// non-serializable shape). Only reachable from [`crate::ipld::encode`].
    EncodeFailed,

    /// A JSON-LD value was not a JSON object where one was required.
    NotAnObject,

    /// A JSON-LD document is missing a field the loader requires.
    MissingField(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidContextCid => f.write_str("sem-ipld: invalid context CID"),
            Self::EncodeFailed => f.write_str("sem-ipld: DAG-CBOR encoding failed"),
            Self::NotAnObject => f.write_str("sem-ipld: expected JSON object"),
            Self::MissingField(name) => {
                write!(f, "sem-ipld: missing required field `{name}`")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Crate-wide `Result` alias.
pub type Result<T> = core::result::Result<T, Error>;

// ─── semver ──────────────────────────────────────────────────────────────────

/// Semver of the overlay itself.
pub const SEM_IPLD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `uor-foundation` version this release has been verified against.
pub const REQUIRED_UOR_FOUNDATION_VERSION: &str = "0.3.0";
