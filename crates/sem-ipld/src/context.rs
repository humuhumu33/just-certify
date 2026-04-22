//! Self-hosted UOR OWL context — pinned by CID.
//!
//! The foundation ontology ships as `artifacts/uor.foundation.jsonld`
//! in the UOR-Framework repo (produced by `spec/src/serializer/jsonld.rs`).
//! sem-ipld's job is to hash those exact bytes once, bind the result to
//! a CID, and surface that CID as a stable `@context` reference.
//!
//! The canonical IRI is deliberately an ordinary string, not a URL to
//! resolve. Permanence is inherited from the CID, not from DNS.

extern crate alloc;
use alloc::string::{String, ToString};

use cid::Cid;

use crate::hasher::{sha256, CODEC_DAG_CBOR};

/// The UOR OWL context descriptor.
#[derive(Clone, Debug)]
pub struct SemanticContext {
    /// The canonical IRI of the ontology's root node.
    pub iri: &'static str,
    /// Textual multibase-`b` CID of the ontology document.
    pub cid: Cid,
}

impl SemanticContext {
    /// The canonical IRI declared by the UOR foundation.
    pub const CANONICAL_IRI: &'static str = "https://uor.foundation/";

    /// Build the descriptor from the raw bytes of the
    /// `uor.foundation.jsonld` file.
    ///
    /// # Errors
    ///
    /// Passes through CID-construction errors from the `cid` crate.
    /// These are unreachable for correct SHA-256 inputs.
    pub fn with_bytes(iri: &'static str, bytes: &[u8]) -> crate::Result<Self> {
        let cid = crate::ipld::cid_from_sha256(CODEC_DAG_CBOR, &sha256(bytes))?;
        Ok(Self { iri, cid })
    }

    /// Emit the short `ipld+cid://<cid>` reference embedded in the
    /// `@context` field.
    #[must_use]
    pub fn jsonld_reference(&self) -> String {
        let mut s = String::with_capacity(32);
        s.push_str("ipld+cid://");
        s.push_str(&self.cid.to_string());
        s
    }
}
