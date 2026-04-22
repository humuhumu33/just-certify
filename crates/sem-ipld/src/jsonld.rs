//! JSON-LD adapter — the outward projection and the inverse parser.
//!
//! Two functions:
//!
//! * [`project_grounded`] renders a `Grounded<T, Tag>` as a JSON-LD
//!   value that references the pinned UOR ontology context by CID.
//! * [`load_as_jsonld`] parses such a value into a neutral
//!   [`SemanticInput`] the caller hands to
//!   `uor_foundation::pipeline::run_*`.
//!
//! This is the Semantic Web half of the overlay; together with
//! [`crate::publish`] (the IPLD half) they compose the full duplex
//! the revised vision names.

extern crate alloc;
use alloc::string::{String, ToString};

use serde_json::{json, Value};
use uor_foundation::enforcement::{ContentAddress, ContentFingerprint, Grounded, GroundedShape};

use crate::context::SemanticContext;
use crate::{Error, Result};

/// Project a `Grounded<T, Tag>` as a JSON-LD value. The caller supplies
/// the domain payload; the overlay wraps it in the standard UOR
/// envelope and pins `@context` via the context descriptor's CID.
///
/// # Errors
///
/// [`Error::NotAnObject`] if `domain_payload` is not a JSON object.
pub fn project_grounded<T, Tag>(
    grounded: &Grounded<T, Tag>,
    context: &SemanticContext,
    domain_payload: Value,
) -> Result<Value>
where
    T: GroundedShape,
{
    let Value::Object(mut map) = domain_payload else {
        return Err(Error::NotAnObject);
    };

    map.insert(
        "u:wittLevelBits".into(),
        Value::Number(grounded.witt_level_bits().into()),
    );
    map.insert(
        "u:unitAddress".into(),
        Value::String(hex_addr(grounded.unit_address())),
    );
    map.insert(
        "u:contentFingerprint".into(),
        Value::String(hex_fp(grounded.content_fingerprint())),
    );
    let cert = grounded.certificate().inner();
    map.insert(
        "u:certificate".into(),
        json!({
            "@type": "u:GroundingCertificate",
            "u:wittBits": cert.witt_bits(),
            "u:contentFingerprint": hex_fp(cert.content_fingerprint()),
        }),
    );

    Ok(json!({
        "@context": [ context.iri, { "u": context.iri } ],
        "@type": "u:Grounded",
        "u:contextCid": context.cid.to_string(),
        "u:payload": Value::Object(map),
    }))
}

// ─── load_as_jsonld — the inverse ────────────────────────────────────────────

/// The parsed, kernel-independent inputs a caller hands to
/// `uor_foundation::pipeline::run_*` to obtain a fresh `Grounded<T>`.
#[derive(Debug, Clone)]
pub struct SemanticInput {
    /// Canonical IRI from `@context`.
    pub context_iri: String,
    /// Multibase-`b` CID of the ontology context, if the document
    /// declared one.
    pub context_cid: Option<String>,
    /// The domain payload (the caller's `T`-shaped data).
    pub payload: Value,
}

/// Parse a JSON-LD value into a [`SemanticInput`] in **lenient mode**.
///
/// Accepts both:
/// * a SemIPLD-shaped object (output of [`project_grounded`]), and
/// * an arbitrary `@context`-bearing JSON-LD document (the framing
///   keys are stripped and the remainder becomes the payload).
///
/// If you need to distinguish a native SemIPLD document from a
/// pass-through, use [`load_as_jsonld_strict`] — it fails on any
/// document that does not carry the SemIPLD envelope.
///
/// # Errors
///
/// [`Error::NotAnObject`] if the top-level value is not an object;
/// [`Error::MissingField`] if `@context` is absent.
pub fn load_as_jsonld(value: &Value) -> Result<SemanticInput> {
    let Value::Object(map) = value else {
        return Err(Error::NotAnObject);
    };

    let context_iri = match map.get("@context") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .find_map(|v| v.as_str().map(ToString::to_string))
            .ok_or(Error::MissingField("@context"))?,
        _ => return Err(Error::MissingField("@context")),
    };

    let context_cid = map
        .get("u:contextCid")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let payload = map.get("u:payload").cloned().unwrap_or_else(|| {
        // Pass-through mode — strip the framing keys and return the rest.
        let mut cleaned = map.clone();
        cleaned.remove("@context");
        cleaned.remove("@type");
        cleaned.remove("u:contextCid");
        Value::Object(cleaned)
    });

    Ok(SemanticInput {
        context_iri,
        context_cid,
        payload,
    })
}

/// Classification of a `load()` result.
#[derive(Debug, Clone)]
pub enum Loaded {
    /// The value carries the full SemIPLD envelope (`@context`,
    /// `u:contextCid`, `u:payload`) — it came from
    /// [`project_grounded`] or a byte-compatible producer.
    SemIpld(SemanticInput),
    /// The value is a valid JSON-LD document with `@context` but no
    /// SemIPLD framing. The payload is everything minus `@context`,
    /// `@type`, and `u:contextCid`.
    PassThrough(SemanticInput),
    /// The value is not a JSON-LD document the loader can handle
    /// (not an object, or missing `@context`).
    NotJsonLd,
}

/// One load function, three classifications. Replaces the
/// [`load_as_jsonld`] / [`load_as_jsonld_strict`] split: callers
/// match on the [`Loaded`] variant and cannot accidentally act on a
/// pass-through as if it were a native SemIPLD document.
#[must_use]
pub fn load(value: &Value) -> Loaded {
    let Value::Object(map) = value else {
        return Loaded::NotJsonLd;
    };
    if !map.contains_key("@context") {
        return Loaded::NotJsonLd;
    }
    let is_sem_ipld =
        map.contains_key("u:contextCid") && map.contains_key("u:payload");
    match load_as_jsonld(value) {
        Ok(input) if is_sem_ipld => Loaded::SemIpld(input),
        Ok(input) => Loaded::PassThrough(input),
        Err(_) => Loaded::NotJsonLd,
    }
}

/// Strict-mode JSON-LD loader. **Only** accepts documents that carry
/// the SemIPLD envelope — `@context`, `u:contextCid`, and `u:payload`
/// must all be present. Pass-through JSON-LD is rejected.
///
/// Use this when you need to be sure the input was produced by
/// [`project_grounded`] (or a byte-compatible producer), not just
/// some other JSON-LD document that happens to have an `@context`.
///
/// # Errors
///
/// [`Error::NotAnObject`] — top level not an object.
/// [`Error::MissingField("@context" | "u:contextCid" | "u:payload")`]
/// — any required envelope field is absent.
pub fn load_as_jsonld_strict(value: &Value) -> Result<SemanticInput> {
    let Value::Object(map) = value else {
        return Err(Error::NotAnObject);
    };
    if !map.contains_key("@context") {
        return Err(Error::MissingField("@context"));
    }
    if !map.contains_key("u:contextCid") {
        return Err(Error::MissingField("u:contextCid"));
    }
    if !map.contains_key("u:payload") {
        return Err(Error::MissingField("u:payload"));
    }
    load_as_jsonld(value)
}

// ─── tiny hex helpers (zero-dep) ─────────────────────────────────────────────

fn hex_addr(a: ContentAddress) -> String {
    let raw = a.as_u128();
    let mut s = String::with_capacity(34);
    s.push_str("0x");
    for i in (0..16).rev() {
        let b = ((raw >> (i * 8)) & 0xff) as u8;
        s.push(nib(b >> 4));
        s.push(nib(b & 0x0f));
    }
    s
}

fn hex_fp(fp: ContentFingerprint) -> String {
    let w = fp.width_bytes() as usize;
    let mut s = String::with_capacity(2 + w * 2);
    s.push_str("0x");
    for &b in &fp.as_bytes()[..w] {
        s.push(nib(b >> 4));
        s.push(nib(b & 0x0f));
    }
    s
}

fn nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}
