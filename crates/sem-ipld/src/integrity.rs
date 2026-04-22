//! SRI-2 `integrity=` attribute emission.
//!
//! The [`Integrity`] type lifts the bare attribute string into a
//! value that carries its own transport contract — the `Accept` header
//! and `?format=` query parameter needed to fetch the exact bytes the
//! SRI string was computed over. Callers that build URLs through
//! [`Integrity::gateway_url`] or [`SemanticBlock::gateway_url`] cannot
//! accidentally hit a public gateway's default decoded response, which
//! is the "first to break" scenario a distributed-systems review
//! specifically flagged. See the module-level scope note below.
//!
//! # ⚠ Scope: what this attribute verifies against
//!
//! A browser loading `<link integrity="sha256-…" href="…">` computes
//! SHA-256 over the response body and matches it against the
//! attribute. Public IPFS gateways serve **decoded** blocks by default:
//!
//! | Block codec  | Gateway default `Content-Type`        |
//! |--------------|---------------------------------------|
//! | `dag-cbor`   | `application/json` or `application/vnd.ipld.dag-json` |
//! | `dag-json`   | `application/json`                    |
//! | `raw`        | `application/octet-stream` (bytes preserved) |
//! | `dag-pb`     | `application/vnd.ipld.dag-pb` (or UnixFS-decoded) |
//!
//! The [`Integrity`] type embeds the two ways (IPIP-402) to force the
//! gateway to return the exact raw bytes:
//!
//! * [`Integrity::REQUIRED_FORMAT_PARAM`] = `"raw"` — append
//!   `?format=raw` to the URL.
//! * [`Integrity::REQUIRED_ACCEPT`] = `"application/vnd.ipld.raw"` —
//!   send this `Accept` header via `fetch()` or server-side proxy.

extern crate alloc;

use alloc::string::String;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cid::Cid;

use crate::hasher::sha256;

/// A formatted SRI-2 attribute *plus* the transport contract it
/// requires. The type exists so that any code path that uses the SRI
/// string must also see the required fetch conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    /// The `"sha256-<base64>"` value that goes into
    /// `<link integrity="…">` / `<script integrity="…">`.
    pub sri: String,
}

impl Integrity {
    /// The `Accept` header an IPFS gateway request must carry so the
    /// raw block bytes are returned unchanged.
    pub const REQUIRED_ACCEPT: &'static str = "application/vnd.ipld.raw";

    /// The query-string parameter value (`?format=raw`) an HTTP
    /// gateway request must carry if the `Accept` header cannot be
    /// set by the client (typical for `<link>`-based SRI).
    pub const REQUIRED_FORMAT_PARAM: &'static str = "raw";

    /// Build an `Integrity` from a byte slice.
    #[must_use]
    pub fn over(bytes: &[u8]) -> Self {
        let digest = sha256(bytes);
        let mut sri = String::with_capacity(7 + 44);
        sri.push_str("sha256-");
        STANDARD.encode_string(digest, &mut sri);
        Self { sri }
    }

    /// Compose a gateway URL that returns the exact bytes this SRI
    /// value verifies against. Appends `?format=raw` — the IPIP-402
    /// query parameter.
    ///
    /// ```text
    /// Integrity::over(block.data_bytes.as_ref())
    ///     .gateway_url("https://ipfs.io", &block.data_cid)
    /// // -> "https://ipfs.io/ipfs/bafyrei…?format=raw"
    /// ```
    #[must_use]
    pub fn gateway_url(&self, base: &str, cid: &Cid) -> String {
        let mut s = String::with_capacity(base.len() + 64);
        s.push_str(base.trim_end_matches('/'));
        s.push_str("/ipfs/");
        // Cid::to_string uses multibase-b32 lowercase — the canonical text form.
        use alloc::string::ToString;
        s.push_str(&cid.to_string());
        s.push_str("?format=");
        s.push_str(Self::REQUIRED_FORMAT_PARAM);
        s
    }
}

/// Plain-function form of [`Integrity::over`]. Kept for callers that
/// want the raw string without the wrapper type.
#[must_use]
pub fn sha256_integrity_attribute(bytes: &[u8]) -> String {
    Integrity::over(bytes).sri
}
