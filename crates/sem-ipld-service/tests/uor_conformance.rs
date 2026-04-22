//! Strict UOR Framework conformance tests for sem-ipld-service.
//!
//! Each test is anchored to a specific clause from the UOR Framework spec at
//! <https://uor-foundation.github.io/UOR-Framework/>.  Namespace references:
//!   * `state:`     → <https://uor.foundation/state/>
//!   * `reduction:` → <https://uor.foundation/reduction/>
//!   * `u:`         → <https://uor.foundation/u/>
//!   * `cert:`      → <https://uor.foundation/cert/>
//!   * JSON-LD 1.1  → <https://www.w3.org/TR/json-ld11/>
//!   * W3C DI 1.0   → <https://www.w3.org/TR/vc-data-integrity/>
//!   * IPIP-402     → <https://specs.ipfs.tech/ipips/ipip-0402/>
//!
//! All tests use `MemoryStore` — no Kubo daemon required.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sem_ipld_service::{router, BlockStore, MemoryStore, ServiceState};
use serde_json::Value;
use tower::ServiceExt;

// ─── harness ─────────────────────────────────────────────────────────────────

fn fresh_state() -> ServiceState {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    ServiceState::new(store).unwrap()
}

/// POST /v1/certify with a JSON payload; return (status, headers, body).
async fn raw_certify(
    state: ServiceState,
    json: &'static str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let app = router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(json))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    (status, headers, body)
}

async fn certify(state: ServiceState, json: &'static str) -> Value {
    let (status, _, body) = raw_certify(state, json).await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

// ─── HTTP conformance ─────────────────────────────────────────────────────────

/// POST /v1/certify MUST return 201 Created (not 200).
/// JSON-LD responses use 201 to signal a newly minted resource.
#[tokio::test]
async fn http_status_is_201_created() {
    let (status, _, _) = raw_certify(fresh_state(), r#"{"conformance":"http_status"}"#).await;
    assert_eq!(status, StatusCode::CREATED, "must be 201 Created");
}

/// Content-Type MUST be `application/ld+json`.
/// W3C JSON-LD 1.1 §B.1 and W3C DI 1.0 §4.1 both mandate this MIME type for
/// JSON-LD documents carrying Data Integrity proofs.
#[tokio::test]
async fn http_content_type_is_application_ld_json() {
    let (_, headers, _) = raw_certify(fresh_state(), r#"{"conformance":"content_type"}"#).await;
    let ct = headers
        .get("content-type")
        .expect("Content-Type must be present")
        .to_str()
        .unwrap();
    assert!(
        ct.contains("application/ld+json"),
        "Content-Type must be application/ld+json, got: {ct}"
    );
}

/// Cache-Control on POST /v1/certify MUST be `public, max-age=300, must-revalidate`.
/// The certify response embeds gateway URLs (host-dependent) so it is NOT
/// immutable. `must-revalidate` prevents stale gateway URLs from being served.
#[tokio::test]
async fn http_certify_cache_control_is_mutable() {
    let (_, headers, _) = raw_certify(fresh_state(), r#"{"conformance":"cache_control"}"#).await;
    let cc = headers
        .get("cache-control")
        .expect("Cache-Control must be present")
        .to_str()
        .unwrap();
    assert_eq!(
        cc, "public, max-age=300, must-revalidate",
        "certify must not be immutable — gateway URLs are host-dependent"
    );
    assert!(
        !cc.contains("immutable"),
        "certify response must NOT carry immutable directive"
    );
}

/// ETag on POST /v1/certify MUST equal the data CID (= `@id` stripped of `ipfs://`).
/// ETag identifies the primary resource; the primary resource is the data block,
/// not the certificate block.
#[tokio::test]
async fn http_etag_matches_data_cid() {
    let (_, headers, body) = raw_certify(fresh_state(), r#"{"conformance":"etag"}"#).await;
    let etag = headers
        .get("etag")
        .expect("ETag must be present")
        .to_str()
        .unwrap();
    let data_cid = body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();
    let expected_etag = format!("\"{data_cid}\"");
    assert_eq!(etag, expected_etag, "ETag must match the data CID");
}

// ─── JSON-LD 1.1 conformance ──────────────────────────────────────────────────

/// `@context` MUST be present and MUST equal `"https://uor.foundation/"`.
/// JSON-LD 1.1 §4.1: the context IRI is the base for all term expansion.
/// SemanticContext::CANONICAL_IRI is the single canonical UOR ontology IRI.
#[tokio::test]
async fn jsonld_context_is_canonical_uor_iri() {
    let body = certify(fresh_state(), r#"{"conformance":"jsonld_context"}"#).await;
    assert_eq!(
        body["@context"].as_str().unwrap(),
        "https://uor.foundation/",
        "state:GroundedContext documents must use the canonical UOR context IRI"
    );
}

/// `@type` MUST be `"https://uor.foundation/state/GroundedContext"` (full IRI).
/// state: namespace spec: GroundedContext is the full-saturation state (σ = 1).
/// CURIEs (e.g. `uor:GroundedContext`) are invalid unless the prefix is defined.
#[tokio::test]
async fn jsonld_type_is_state_grounded_context() {
    let body = certify(fresh_state(), r#"{"conformance":"jsonld_type"}"#).await;
    assert_eq!(
        body["@type"].as_str().unwrap(),
        "https://uor.foundation/state/GroundedContext",
        "@type must be the full state:GroundedContext IRI"
    );
}

/// `@context` MUST appear as the first key in the serialised JSON object.
/// JSON-LD 1.1 §8.1: processors rely on context appearing before other terms.
#[tokio::test]
async fn jsonld_context_is_first_key() {
    let (_, _, _body) = raw_certify(fresh_state(), r#"{"conformance":"key_order"}"#).await;
    // Re-fetch as raw bytes to inspect serialisation order.
    let state = fresh_state();
    let app = router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(r#"{"conformance":"key_order"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let raw = std::str::from_utf8(&bytes).unwrap();
    let ctx_pos = raw.find("\"@context\"").expect("@context must be present");
    let type_pos = raw.find("\"@type\"").expect("@type must be present");
    let id_pos = raw.find("\"@id\"").expect("@id must be present");
    assert!(
        ctx_pos < type_pos,
        "@context ({ctx_pos}) must precede @type ({type_pos})"
    );
    assert!(
        ctx_pos < id_pos,
        "@context ({ctx_pos}) must precede @id ({id_pos})"
    );
}

/// `@id` MUST be an `ipfs://` URI (CIDv1, base32 lowercase).
/// The `ipfs://` scheme signals a permanent, content-addressed location
/// resolvable from any IPFS gateway without registry trust.
#[tokio::test]
async fn jsonld_id_is_ipfs_cid_v1() {
    let body = certify(fresh_state(), r#"{"conformance":"id_format"}"#).await;
    let id = body["@id"].as_str().unwrap();
    assert!(id.starts_with("ipfs://"), "@id must start with ipfs://");
    let cid_str = id.strip_prefix("ipfs://").unwrap();
    // CIDv1 base32 starts with `bafyrei` (sha2-256 multihash in base32).
    assert!(
        cid_str.starts_with("bafyrei"),
        "@id CID must be CIDv1 base32 (bafyrei…), got: {cid_str}"
    );
    // Must parse as a valid CID.
    cid::Cid::try_from(cid_str).expect("@id must be a valid CIDv1");
}

/// `certificate` MUST be an `ipfs://` CIDv1 URI (the GroundingCertificate block).
/// cert: namespace: the GroundingCertificate attests the pipeline admission proof.
#[tokio::test]
async fn jsonld_certificate_is_ipfs_cid_v1() {
    let body = certify(fresh_state(), r#"{"conformance":"cert_format"}"#).await;
    let cert = body["certificate"].as_str().unwrap();
    assert!(
        cert.starts_with("ipfs://"),
        "certificate must start with ipfs://"
    );
    let cid_str = cert.strip_prefix("ipfs://").unwrap();
    assert!(
        cid_str.starts_with("bafyrei"),
        "certificate CID must be CIDv1 base32, got: {cid_str}"
    );
    cid::Cid::try_from(cid_str).expect("certificate must be a valid CIDv1");
}

/// `@id` and `certificate` MUST be distinct CIDs.
/// They address different blocks: the data block and the certificate block.
#[tokio::test]
async fn jsonld_id_and_certificate_are_distinct() {
    let body = certify(fresh_state(), r#"{"conformance":"distinct_cids"}"#).await;
    assert_ne!(
        body["@id"], body["certificate"],
        "@id (data) and certificate must address different blocks"
    );
}

// ─── state: namespace conformance ─────────────────────────────────────────────

/// `state:GroundedContext` requires full saturation: σ = 1, freeRank = 0.
/// Verified indirectly: `pipeline::run` returns `Ok(Grounded)` only when the
/// reduction reaches convergence without contradiction or stall.
/// A `PipelineFailure` would mean the grounded state is not fully saturated.
#[tokio::test]
async fn state_grounded_context_pipeline_succeeds() {
    // The handler returns 201 iff pipeline::run returned Ok. Any pipeline
    // failure maps to 500 Internal Server Error.
    let (status, _, _) = raw_certify(fresh_state(), r#"{"conformance":"grounded_context"}"#).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "pipeline::run must succeed — GroundedContext requires σ = 1 (full saturation)"
    );
}

/// The response MUST contain `foundation_version` matching the compiled
/// `sem_ipld::REQUIRED_UOR_FOUNDATION_VERSION` constant.
/// This pins the semantic guarantees to the exact kernel version that ran.
#[tokio::test]
async fn state_foundation_version_present_and_non_empty() {
    let body = certify(fresh_state(), r#"{"conformance":"foundation_version"}"#).await;
    let v = body["foundation_version"].as_str().unwrap();
    assert!(!v.is_empty(), "foundation_version must be non-empty");
    // Must be semver-shaped: digits separated by dots.
    assert!(
        v.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "foundation_version must be a semver string, got: {v}"
    );
}

// ─── reduction: namespace conformance ────────────────────────────────────────

/// Budget solvency check (reduction:BudgetSolvencyCheck, order=0):
/// `thermodynamicBudget ≥ bitsWidth(unitWittLevel) × ln2`.
/// Our config: budget=1024, WittLevel::W8 → bitsWidth=8, 8×ln2 ≈ 5.55.
/// 1024 >> 5.55 — solvency is satisfied with orders of magnitude to spare.
/// Verified by pipeline::run not returning BudgetSolvency PipelineFailure.
#[test]
fn reduction_budget_solvency_constraint() {
    use sem_ipld::prelude::SriHasher256;
    use uor_foundation::enforcement::{CompileUnitBuilder, ConstrainedTypeInput, Term};
    use uor_foundation::enums::{VerificationDomain, WittLevel};
    use uor_foundation::pipeline;

    let terms = [Term::Literal {
        value: 1,
        level: WittLevel::W8,
    }];
    let domains = [VerificationDomain::Enumerative];
    let validated = CompileUnitBuilder::new()
        .root_term(&terms)
        .witt_level_ceiling(WittLevel::W8)
        .thermodynamic_budget(1024)
        .target_domains(&domains)
        .result_type::<ConstrainedTypeInput>()
        .validate()
        .expect("CompileUnit must pass validation (budget solvency)");
    let grounded = pipeline::run::<ConstrainedTypeInput, _, SriHasher256>(validated)
        .expect("pipeline::run must succeed — all 6 preflight checks and 6 reduction stages");
    // Grounded means σ = 1. The unit_address is non-zero for any successful run.
    assert!(
        !grounded.unit_address().is_zero(),
        "unit_address must be non-zero after successful pipeline run"
    );
}

/// The CompileUnit type IRI MUST be the canonical UOR type IRI.
/// reduction: namespace: CompileUnit::unitAddress is a u:Element with IRI
/// `https://uor.foundation/type/ConstrainedType`.
#[test]
fn reduction_compile_unit_type_iri_is_canonical() {
    use uor_foundation::enforcement::ConstrainedTypeInput;
    use uor_foundation::pipeline::ConstrainedTypeShape;
    assert_eq!(
        ConstrainedTypeInput::IRI,
        "https://uor.foundation/type/ConstrainedType",
        "ConstrainedTypeInput::IRI must match the reduction: namespace spec"
    );
}

// ─── u: namespace conformance (content addressing) ───────────────────────────

/// `uor_address` MUST use multibase base58btc encoding (z-prefix).
/// u: namespace: content-addressable identifiers use base58btc per the
/// UOR multibase convention for compact 16-byte handles.
#[tokio::test]
async fn u_uor_address_uses_base58btc_multibase() {
    let body = certify(fresh_state(), r#"{"conformance":"uor_address_format"}"#).await;
    let ua = body["uor_address"].as_str().unwrap();
    assert!(
        ua.starts_with('z'),
        "uor_address must start with 'z' (multibase base58btc prefix), got: {ua}"
    );
    // Decode must succeed and yield exactly 16 bytes.
    let decoded = sem_ipld_service::multibase_util::decode_multibase(ua)
        .expect("uor_address must be valid multibase");
    assert_eq!(
        decoded.len(),
        16,
        "uor_address must encode exactly 16 bytes (128-bit content handle)"
    );
}

/// `uor_address` MUST be content-derived: different payloads MUST produce
/// different addresses. This tests the u: namespace guarantee that each
/// `u:Element` carries a unique content-derived identifier.
#[tokio::test]
async fn u_uor_address_is_content_derived() {
    let a = certify(
        fresh_state(),
        r#"{"conformance":"u_content_derived","v":1}"#,
    )
    .await;
    let b = certify(
        fresh_state(),
        r#"{"conformance":"u_content_derived","v":2}"#,
    )
    .await;
    assert_ne!(
        a["uor_address"], b["uor_address"],
        "u: content-addressing: different payloads must produce different uor_address"
    );
}

/// `uor_address` MUST be deterministic: identical payloads MUST always
/// produce the same address (u: functional property, single-valued).
#[tokio::test]
async fn u_uor_address_is_deterministic() {
    let state = fresh_state();
    let a = certify(state.clone(), r#"{"conformance":"u_deterministic"}"#).await;
    let b = certify(state.clone(), r#"{"conformance":"u_deterministic"}"#).await;
    let c = certify(state, r#"{"conformance":"u_deterministic"}"#).await;
    assert_eq!(
        a["uor_address"], b["uor_address"],
        "uor_address must be deterministic (A == B)"
    );
    assert_eq!(
        b["uor_address"], c["uor_address"],
        "uor_address must be deterministic (B == C)"
    );
}

/// `uor_address` 16-byte payload MUST equal the first 16 bytes of the
/// data CID's SHA-256 digest. This grounds `uor_address` in the u:digest
/// / u:canonicalBytes semantics of the u: namespace.
#[tokio::test]
async fn u_uor_address_grounded_in_cid_digest() {
    let body = certify(fresh_state(), r#"{"conformance":"u_cid_grounding","x":99}"#).await;

    let ua_bytes =
        sem_ipld_service::multibase_util::decode_multibase(body["uor_address"].as_str().unwrap())
            .unwrap();

    let cid_str = body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();
    let cid = cid::Cid::try_from(cid_str).unwrap();
    let digest = cid.hash().digest();

    assert_eq!(
        ua_bytes.as_slice(),
        &digest[..16],
        "uor_address bytes must equal the first 16 bytes of the data CID SHA-256 digest"
    );
}

// ─── W3C Data Integrity 1.0 conformance ──────────────────────────────────────

/// `digestMultibase` MUST use the `u` prefix (Base64Url multibase).
/// W3C DI 1.0 §3.3.1: the `digestMultibase` value is a multibase-encoded
/// multihash of the canonical document. Base64Url (`u`) is the DI-canonical
/// multibase for SHA-256 multihashes.
#[tokio::test]
async fn di_digest_multibase_uses_base64url() {
    let body = certify(fresh_state(), r#"{"conformance":"di_multibase"}"#).await;
    let dm = body["digestMultibase"].as_str().unwrap();
    assert!(
        dm.starts_with('u'),
        "digestMultibase must start with 'u' (Base64Url multibase), got: {dm}"
    );
}

/// `digestMultibase` decoded bytes MUST start with SHA-256 multihash preamble
/// `\x12\x20` (hash function code 0x12, digest length 0x20 = 32).
/// W3C DI 1.0 §3.3.1 + Multihash spec.
#[tokio::test]
async fn di_digest_multibase_contains_sha256_multihash() {
    let body = certify(fresh_state(), r#"{"conformance":"di_multihash"}"#).await;
    let dm = body["digestMultibase"].as_str().unwrap();
    let decoded = sem_ipld_service::multibase_util::decode_multibase(dm)
        .expect("digestMultibase must be valid multibase");
    assert!(
        decoded.len() >= 34,
        "decoded digestMultibase must be at least 34 bytes (2 preamble + 32 digest)"
    );
    assert_eq!(
        decoded[0], 0x12,
        "multihash function code must be 0x12 (SHA-256)"
    );
    assert_eq!(
        decoded[1], 0x20,
        "multihash digest length must be 0x20 (32 bytes)"
    );
}

/// `digestMultibase` 32-byte SHA-256 digest MUST match the data CID digest.
/// Both the CID and `digestMultibase` are derived from the same canonical bytes.
#[tokio::test]
async fn di_digest_multibase_matches_cid_digest() {
    let body = certify(fresh_state(), r#"{"conformance":"di_digest_match","y":7}"#).await;

    let dm = body["digestMultibase"].as_str().unwrap();
    let decoded = sem_ipld_service::multibase_util::decode_multibase(dm).unwrap();
    let dm_digest = &decoded[2..]; // strip multihash preamble

    let cid_str = body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();
    let cid = cid::Cid::try_from(cid_str).unwrap();
    let cid_digest = cid.hash().digest();

    assert_eq!(
        dm_digest, cid_digest,
        "digestMultibase SHA-256 must match the data CID digest"
    );
}

// ─── SRI-2 conformance ────────────────────────────────────────────────────────

/// `integrity` MUST be a valid SRI-2 hash expression (`sha256-<base64>`).
/// Drop-in compatible with HTML `<link integrity="…">` and CDN integrity checks.
#[tokio::test]
async fn sri_integrity_field_format() {
    let body = certify(fresh_state(), r#"{"conformance":"sri_format"}"#).await;
    let integrity = body["integrity"].as_str().unwrap();
    assert!(
        integrity.starts_with("sha256-"),
        "integrity must start with 'sha256-', got: {integrity}"
    );
    let b64 = integrity.strip_prefix("sha256-").unwrap();
    // Base64 standard: 44 chars for 32 bytes (32*4/3 rounded up to multiple of 4).
    assert_eq!(
        b64.len(),
        44,
        "integrity sha256 base64 must be 44 chars (32 bytes), got len={}",
        b64.len()
    );
    // Must decode without error.
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("integrity base64 must decode successfully");
}

/// `integrity` SHA-256 digest MUST match the data CID digest.
#[tokio::test]
async fn sri_integrity_matches_cid_digest() {
    let body = certify(fresh_state(), r#"{"conformance":"sri_digest_match","z":3}"#).await;

    use base64::Engine as _;
    let b64 = body["integrity"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256-")
        .unwrap();
    let integrity_digest = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();

    let cid_str = body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();
    let cid = cid::Cid::try_from(cid_str).unwrap();

    assert_eq!(
        integrity_digest.as_slice(),
        cid.hash().digest(),
        "integrity SHA-256 must match the data CID digest"
    );
}

// ─── IPIP-402 block-GET conformance ───────────────────────────────────────────

/// `GET /v1/blocks/{cid}` MUST return `Cache-Control: public, max-age=31536000, immutable`.
/// IPIP-402: blocks are content-addressed; the CID→bytes mapping is
/// mathematically immutable. One-year TTL with `immutable` is required.
#[tokio::test]
async fn ipip402_block_get_cache_control_is_immutable() {
    let state = fresh_state();
    let app = router(state);

    let post = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(r#"{"conformance":"ipip402_cache"}"#))
        .unwrap();
    let post_resp = app.clone().oneshot(post).await.unwrap();
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let post_body: Value = serde_json::from_slice(&post_bytes).unwrap();
    let cid = post_body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();

    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/blocks/{cid}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let cc = get_resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        cc, "public, max-age=31536000, immutable",
        "IPIP-402: block GET must carry immutable cache directive"
    );
}

/// `GET /v1/blocks/{cid}` ETag MUST equal the CID string (quoted).
/// IPIP-402: the ETag for a content-addressed block is the CID itself.
#[tokio::test]
async fn ipip402_block_get_etag_is_cid() {
    let state = fresh_state();
    let app = router(state);

    let post = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(r#"{"conformance":"ipip402_etag"}"#))
        .unwrap();
    let post_resp = app.clone().oneshot(post).await.unwrap();
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let post_body: Value = serde_json::from_slice(&post_bytes).unwrap();
    let cid_str = post_body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();

    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/blocks/{cid_str}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get).await.unwrap();
    let etag = get_resp.headers().get("etag").unwrap().to_str().unwrap();
    assert_eq!(
        etag,
        format!("\"{cid_str}\""),
        "IPIP-402: block GET ETag must be the quoted CID"
    );
}

/// Unknown CID returns 404 — the block-GET endpoint is faithful to what was stored.
/// Certify on one state, then GET on a fresh state that has no blocks.
#[tokio::test]
async fn ipip402_unknown_cid_returns_404() {
    // Obtain a genuine CIDv1 by certifying on a throwaway store.
    let cid_str = {
        let body = certify(fresh_state(), r#"{"conformance":"ipip402_404"}"#).await;
        body["@id"]
            .as_str()
            .unwrap()
            .strip_prefix("ipfs://")
            .unwrap()
            .to_owned()
    };

    // A fresh store has never seen this CID — must return 404.
    let app = router(fresh_state());
    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/blocks/{cid_str}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "block GET for a CID not in this store must return 404"
    );
}

// ─── idempotency (UOR content-addressing invariant) ───────────────────────────

/// Certifying the same payload twice MUST return identical `@id` and
/// `certificate`. UOR content-addressing guarantees: same input → same output.
#[tokio::test]
async fn content_addressing_is_idempotent() {
    let state = fresh_state();
    let a = certify(state.clone(), r#"{"conformance":"idempotency","n":1}"#).await;
    let b = certify(state, r#"{"conformance":"idempotency","n":1}"#).await;
    assert_eq!(a["@id"], b["@id"], "@id must be idempotent");
    assert_eq!(
        a["certificate"], b["certificate"],
        "certificate must be idempotent"
    );
    assert_eq!(
        a["uor_address"], b["uor_address"],
        "uor_address must be idempotent"
    );
    assert_eq!(
        a["integrity"], b["integrity"],
        "integrity must be idempotent"
    );
}

// ─── integrity field vs raw block bytes ──────────────────────────────────────

/// The `integrity` field MUST equal SHA-256 of the raw bytes returned by
/// `GET /v1/blocks/<data_cid>` (the CBOR block bytes, NOT the JSON input and
/// NOT the decoded text).  An auditor who fetches the block and computes
/// SHA-256 of the raw HTTP response body gets the same value as `integrity`.
///
/// This test closes the "integrity mismatch" concern raised in external stress
/// tests: the mismatch was caused by computing SHA-256 over decoded/text bytes
/// rather than the raw binary CBOR block.
#[tokio::test]
async fn integrity_matches_sha256_of_raw_get_block_bytes() {
    let state = fresh_state();
    let app = router(state);

    // Certify something.
    let post = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(
            r#"{"conformance":"integrity_raw_bytes","source":"def f(): pass"}"#,
        ))
        .unwrap();
    let post_resp = app.clone().oneshot(post).await.unwrap();
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let post_body: Value = serde_json::from_slice(&post_bytes).unwrap();

    let integrity_field = post_body["integrity"].as_str().unwrap();
    let cid_str = post_body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();

    // Retrieve the raw block bytes.
    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/blocks/{cid_str}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let raw_block_bytes = axum::body::to_bytes(get_resp.into_body(), 1 << 20)
        .await
        .unwrap();

    // Compute SHA-256 of the raw block bytes (binary, NOT text).
    // Uses the same hasher as the service — no external crate required.
    use base64::Engine as _;
    let computed_digest = sem_ipld::hasher::sha256(&raw_block_bytes);
    let computed_sri = format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(computed_digest)
    );

    assert_eq!(
        computed_sri, integrity_field,
        "SHA-256 of the raw CBOR block bytes (from GET /v1/blocks/<cid>) must \
         equal the integrity field.  Mismatch means you computed SHA-256 over \
         decoded text or JSON input instead of the raw binary block."
    );
}
