//! sem-ipld-service — the HTTP surface. v0.2.0.
//!
//! v0.2.0 swaps the in-memory block store for a durable local Kubo
//! sidecar (IPFS daemon on the same machine, HTTP RPC at
//! `127.0.0.1:5001` by default). The v0.1.x `Cache-Control: immutable`
//! directive is restored on `GET /v1/blocks/{cid}` because the
//! underlying promise is finally keepable. `POST /v1/certify`
//! intentionally stays at `max-age=300, must-revalidate` — its
//! response body carries `urls.data` / `urls.cert` that can point at
//! different hosts across deployments, so the response itself is not
//! immutable even when the blocks it references are.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// CryptoError / ApiError variants carry CIDs / descriptive messages
// whose size (>128 bytes) trips `result_large_err`. The size is
// semantic — callers need the full context to diagnose — so we
// allow the lint at crate level rather than box every variant.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cid::Cid;
use serde::{Deserialize, Serialize};

use sem_ipld::prelude::*;
use uor_foundation::enforcement::{CompileUnitBuilder, ConstrainedTypeInput, Term};
use uor_foundation::enums::{VerificationDomain, WittLevel};
use uor_foundation::pipeline;

pub mod store;
pub use store::{BlockStore, CachedStore, KuboStore, MemoryStore, StoreError};

pub mod multibase_util;
pub mod projection;

/// v0.4.0 signing configuration. When `Some(_)`, the service's VC
/// projection uses `uor-dag-cbor-ed25519-2025` with the embedded key;
/// when `None`, it uses the unsigned `uor-dag-cbor-2025` (v0.3.0 path).
#[derive(Clone)]
pub struct SigningConfig {
    /// The parsed Ed25519 signing key.
    pub signing_key: ed25519_dalek::SigningKey,
    /// Cached verifying key (derived from the signing key).
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Precomputed `z6Mk…` multibase form of the public key.
    pub public_multikey: String,
}

impl SigningConfig {
    /// Parse a base64-encoded 32-byte seed (the
    /// `SEM_IPLD_ISSUER_KEY_B64` env var).
    ///
    /// # Errors
    ///
    /// Returns a `String` with a human-readable failure reason on
    /// bad base64, wrong length, etc. Intended to be logged and
    /// exited on at startup.
    pub fn from_base64_seed(seed_b64: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let seed_bytes = base64::engine::general_purpose::STANDARD
            .decode(seed_b64)
            .map_err(|e| format!("SEM_IPLD_ISSUER_KEY_B64 not valid base64: {e}"))?;
        if seed_bytes.len() != 32 {
            return Err(format!(
                "SEM_IPLD_ISSUER_KEY_B64 must decode to 32 bytes, got {}",
                seed_bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&arr);
        let verifying_key = signing_key.verifying_key();
        let public_multikey = uor_vc_crypto::ed25519_public_multikey(&verifying_key);
        Ok(Self {
            signing_key,
            verifying_key,
            public_multikey,
        })
    }
}

/// Default UOR OWL context bytes.
pub const DEFAULT_CONTEXT_BYTES: &[u8] =
    br#"{"@context":{"u":"https://uor.foundation/","xsd":"http://www.w3.org/2001/XMLSchema#"}}"#;

/// Max body size for `application/json` requests (10 MB).
pub const JSON_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// Max body size for opaque / dag-cbor requests (100 MB).
pub const OPAQUE_BODY_LIMIT_BYTES: usize = 100 * 1024 * 1024;

/// Service state.
#[derive(Clone)]
pub struct ServiceState {
    /// The pinned UOR OWL context.
    pub context: SemanticContext,
    /// Durable block store behind the trait. v0.2.0: typically
    /// `CachedStore<KuboStore>`; `MemoryStore` under tests.
    pub store: Arc<dyn BlockStore>,
    /// Optional absolute base URL override.
    pub public_base_url: Option<String>,
    /// v0.4.0: Ed25519 issuer key, if configured. When present, VC
    /// projections emit `uor-dag-cbor-ed25519-2025` proofs; when
    /// absent, they emit the v0.3.0 unsigned `uor-dag-cbor-2025`.
    pub signing: Option<SigningConfig>,
}

impl ServiceState {
    /// Build a fresh state.
    ///
    /// # Errors
    ///
    /// Returns [`sem_ipld::Error`] if the context bytes cannot be hashed.
    pub fn new(store: Arc<dyn BlockStore>) -> Result<Self, sem_ipld::Error> {
        Ok(Self {
            context: SemanticContext::with_bytes(
                SemanticContext::CANONICAL_IRI,
                DEFAULT_CONTEXT_BYTES,
            )?,
            store,
            public_base_url: std::env::var("PUBLIC_BASE_URL").ok(),
            signing: None,
        })
    }

    /// Builder-style signer installer. `main` uses this after parsing
    /// the env; tests typically leave it unset.
    #[must_use]
    pub fn with_signing(mut self, signing: SigningConfig) -> Self {
        self.signing = Some(signing);
        self
    }
}

/// Build the full router.
pub fn router(state: ServiceState) -> Router {
    Router::new()
        .route("/v1/certify", post(certify_handler))
        .route("/v1/blocks/:cid", get(block_handler))
        .route("/v1/health", get(health_handler))
        .route("/v1/openapi.yaml", get(openapi_handler))
        // AI-agent discovery: OpenAI plugin manifest + function-calling schema.
        .route("/.well-known/ai-plugin.json", get(ai_plugin_handler))
        .route("/v1/openai-tools", get(openai_tools_handler))
        .layer(DefaultBodyLimit::max(OPAQUE_BODY_LIMIT_BYTES))
        .with_state(state)
}

// ─── response schema ─────────────────────────────────────────────────────────

/// Response body for `POST /v1/certify`.
///
/// A valid JSON-LD 1.1 node. Field order is declaration order (serde
/// preserves it), matching the W3C convention: `@context` → `@type` →
/// identity fields → proof fields → convenience layer.
///
/// One-line story: UOR admitted the object → assigned `uor_address` →
/// that maps 1-to-1 to the content-addressed IPFS URI in `@id`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertifyResponse {
    /// JSON-LD 1.1 context — the UOR ontology IRI that defines every
    /// term in this document. Parseable by any JSON-LD processor.
    #[serde(rename = "@context")]
    pub context_iri: String,
    /// JSON-LD type — full IRI, no prefix expansion needed. Any
    /// JSON-LD processor resolves this without fetching the context.
    #[serde(rename = "@type")]
    pub object_type: &'static str,
    /// UOR kernel's canonical name: multibase base58btc (`z`-prefix)
    /// over the 16-byte big-endian unit address. This is the result of
    /// UOR name-resolution — the stable ontological identity before any
    /// IPFS mapping.
    pub uor_address: String,
    /// JSON-LD canonical identifier: `ipfs://<data_cid>`. Permanent,
    /// gateway-independent, and globally retrievable from any public
    /// IPFS node. The content-addressed counterpart to `uor_address`.
    #[serde(rename = "@id")]
    pub id: String,
    /// `ipfs://<certificate_cid>` — IPFS URI of the UOR admission proof
    /// (DAG-CBOR block). Resolve via the `gateway.vc` URL for the W3C
    /// Verifiable Credential 2.0 projection.
    pub certificate: String,
    /// SRI-2 `sha256-<base64>` over the data-block bytes. Drop directly
    /// into an HTML `<link integrity="…">` tag or CDN integrity check.
    pub integrity: String,
    /// W3C Data Integrity 1.0 canonical digest: Base64Url multibase over
    /// the multihash envelope (0x12, 0x20, digest). Interoperable with
    /// any DI 1.0 verifier.
    #[serde(rename = "digestMultibase")]
    pub digest_multibase: String,
    /// `uor-foundation` kernel version that ran the admission pipeline.
    pub foundation_version: String,
    /// HTTP convenience endpoints — secondary to the canonical IPFS
    /// URIs above. Use `@id` / `certificate` for durable references.
    pub gateway: Gateway,
}

/// HTTP gateway convenience endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct Gateway {
    /// Raw IPLD data block (codec-faithful bytes, IPIP-402).
    pub data: String,
    /// Raw IPLD certificate block bytes.
    pub cert: String,
    /// Certificate as a JSON-LD document (`application/ld+json`).
    pub jsonld: String,
    /// Certificate as a W3C VC 2.0 credential (`application/vc+ld+json`).
    pub vc: String,
}

/// `GET /v1/health` body on success.
#[derive(Debug, Serialize)]
pub struct HealthOk {
    /// Fixed string `"ok"`.
    pub status: &'static str,
    /// Backend descriptor returned by `BlockStore::ping` — e.g.
    /// `"kubo 0.30.0"`, `"memory"`.
    pub store: String,
}

/// `GET /v1/health` body on backend failure.
#[derive(Debug, Serialize)]
pub struct HealthDegraded {
    /// Fixed string `"degraded"`.
    pub status: &'static str,
    /// Specific failure message from the backend.
    pub error: String,
}

// ─── URL derivation ─────────────────────────────────────────────────────────

fn derive_base_url(state: &ServiceState, headers: &HeaderMap) -> String {
    if let Some(configured) = state.public_base_url.as_deref() {
        return configured.trim_end_matches('/').to_string();
    }
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| "http".into());
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{scheme}://{host}")
}

// ─── cache headers ──────────────────────────────────────────────────────────
//
// v0.2.0: the two endpoints diverge on cache policy, intentionally.
//
// * `POST /v1/certify` returns `urls.data` / `urls.cert` that embed the
//   service's own host (derived from Host / X-Forwarded-*). Those URLs
//   can legitimately change across deployments, so the response itself
//   is NOT immutable. 5 minutes of freshness + must-revalidate is the
//   right header here.
// * `GET /v1/blocks/{cid}` returns content addressed by a CID. The
//   CID → bytes mapping is mathematically immutable; the backing
//   Kubo daemon pins the block so it won't be GC'd. `immutable` is
//   the correct header, and v0.2.0 restores it — this is the whole
//   point of the release.
const CACHE_CONTROL_CERTIFY: &str = "public, max-age=300, must-revalidate";
const CACHE_CONTROL_BLOCK: &str = "public, max-age=31536000, immutable";

// ─── JSON integer range validator (FIX 2 from v0.1.1) ────────────────────────

fn walk_reject_bignums(v: &serde_json::Value) -> Result<(), ApiError> {
    match v {
        serde_json::Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                return Ok(());
            }
            let f = n.as_f64().ok_or_else(|| ApiError::BadRequest {
                error: "non-finite number",
                detail: "JSON numbers must be finite floats".into(),
            })?;
            if !f.is_finite() {
                return Err(ApiError::BadRequest {
                    error: "non-finite number",
                    detail: "DAG-CBOR forbids NaN and Infinity".into(),
                });
            }
            if f.fract() == 0.0 {
                return Err(ApiError::BadRequest {
                    error: "integer out of DAG-CBOR range",
                    detail: "DAG-CBOR integers must fit in i64 or u64; \
                             arbitrary-precision bignums (CBOR tag 2) are \
                             not supported in this version. Encode large \
                             values as byte strings instead."
                        .into(),
                });
            }
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk_reject_bignums(item)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for val in map.values() {
                walk_reject_bignums(val)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ─── handlers ────────────────────────────────────────────────────────────────

/// Map a [`StoreError`] to the right HTTP shape.
fn map_store_err(e: StoreError) -> ApiError {
    match e {
        StoreError::Unreachable(msg) => {
            tracing::warn!(reason = %msg, "store unreachable");
            ApiError::ServiceUnavailable("storage backend unavailable".into())
        }
        StoreError::CidMismatch { expected, got } => {
            tracing::error!(
                %expected, %got,
                "CID MISMATCH — content-addressing invariant violated"
            );
            ApiError::Internal("integrity invariant violated".into())
        }
        StoreError::Backend(msg) => ApiError::Internal(msg),
    }
}

async fn certify_handler(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    // 1. Run the UOR admission pipeline.
    //    unit_address from pipeline::run is a type-class identifier — it names
    //    the certification schema (ConstrainedTypeInput at W8, budget 1024),
    //    not the individual object.  We derive uor_address from the data block's
    //    CID digest below (step 4) so it is unique and content-specific.
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
        .map_err(|e| ApiError::Internal(format!("CompileUnit validation: {e:?}")))?;
    let grounded: uor_foundation::Grounded<ConstrainedTypeInput> =
        pipeline::run::<ConstrainedTypeInput, _, SriHasher256>(validated)
            .map_err(|e| ApiError::Internal(format!("pipeline::run: {e:?}")))?;

    // 2. Route by Content-Type.
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    // v0.4.0 T5: detect unrecognized Content-Types so we can attach
    // an RFC 7234 Warning: 299 header to the response. The routing
    // behavior is preserved — anything unknown still goes to the
    // raw-bytes path — but callers now get a loud signal that they
    // may not have gotten the structured encoding they expected.
    let ct_header_present = headers.get(header::CONTENT_TYPE).is_some();
    let ct_is_recognized = content_type.starts_with("application/json")
        || content_type.starts_with("application/vnd.ipld.dag-cbor")
        || content_type.starts_with("application/octet-stream");
    let emit_warning_header = !ct_header_present || !ct_is_recognized;

    let block = if content_type.starts_with("application/json") {
        if body.len() > JSON_BODY_LIMIT_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "JSON body {} exceeds {JSON_BODY_LIMIT_BYTES}-byte limit",
                body.len()
            )));
        }
        let payload: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| ApiError::BadRequest {
                error: "malformed JSON",
                detail: e.to_string(),
            })?;
        walk_reject_bignums(&payload)?;
        publish_semantic(&grounded, &state.context, payload)
            .map_err(|e| ApiError::Internal(format!("publish_semantic: {e}")))?
    } else if content_type.starts_with("application/vnd.ipld.dag-cbor") {
        use ipld_core::ipld::Ipld;
        let decoded: Ipld =
            serde_ipld_dagcbor::from_slice(&body).map_err(|e| ApiError::BadRequest {
                error: "malformed DAG-CBOR",
                detail: e.to_string(),
            })?;
        let reencoded = serde_ipld_dagcbor::to_vec(&decoded)
            .map_err(|e| ApiError::Internal(format!("dag-cbor re-encode: {e}")))?;
        if reencoded.as_slice() != body.as_ref() {
            return Err(ApiError::BadRequest {
                error: "non-canonical DAG-CBOR",
                detail: "input bytes do not match the canonical DAG-CBOR \
                         encoding of their decoded value"
                    .into(),
            });
        }
        sem_ipld::publish::publish_parts(
            &state.context,
            &decoded,
            grounded.certificate().inner().witt_bits(),
            grounded.witt_level_bits(),
            grounded.unit_address().as_u128(),
            grounded.content_fingerprint(),
        )
        .map_err(|e| ApiError::Internal(format!("publish dag-cbor: {e}")))?
    } else {
        if !content_type.starts_with("application/octet-stream") {
            tracing::warn!(
                content_type = %content_type,
                "unrecognised content-type — routing to raw-bytes path"
            );
        }
        use uor_foundation::enforcement::ContentFingerprint;
        let fp = ContentFingerprint::from_buffer(sem_ipld::hasher::sha256(&body), 32);
        sem_ipld::publish::publish_raw(
            &state.context,
            &body,
            grounded.certificate().inner().witt_bits(),
            grounded.witt_level_bits(),
            grounded.unit_address().as_u128(),
            fp,
        )
        .map_err(|e| ApiError::Internal(format!("publish_raw: {e}")))?
    };

    // 3. Store both blocks durably. Put is idempotent by CID; the
    //    cached store write-through means a subsequent GET hits the
    //    LRU on the same pod for free.
    state
        .store
        .put(&block.data_cid, &block.data_bytes)
        .await
        .map_err(map_store_err)?;
    state
        .store
        .put(&block.certificate_cid, &block.certificate_bytes)
        .await
        .map_err(map_store_err)?;

    // 4. Build absolute URLs.
    let base = derive_base_url(&state, &headers);
    let data_cid_str = block.data_cid.to_string();
    let cert_cid_str = block.certificate_cid.to_string();

    // digestMultibase: W3C-canonical form of the SHA-256 digest.
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&block.data_cid.hash().digest()[..32]);
    let digest_multibase = crate::multibase_util::sha256_digest_multibase(&digest);

    // uor_address: content-derived 128-bit address — first 16 bytes of the
    // data CID's SHA-256 digest, encoded as multibase base58btc (z-prefix).
    // Unique per object, deterministic, and grounded in the UOR content-addressing
    // namespace (u:digest / u:canonicalBytes per the framework spec).
    let cid_digest = block.data_cid.hash().digest();
    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&cid_digest[..16]);
    let unit_address = crate::multibase_util::encode_base58btc(&addr_bytes);

    let response_body = CertifyResponse {
        context_iri: state.context.iri.to_string(),
        object_type: "https://uor.foundation/state/GroundedContext",
        uor_address: unit_address,
        id: format!("ipfs://{data_cid_str}"),
        certificate: format!("ipfs://{cert_cid_str}"),
        integrity: block.integrity_attr.clone(),
        digest_multibase,
        foundation_version: sem_ipld::REQUIRED_UOR_FOUNDATION_VERSION.into(),
        gateway: Gateway {
            data: format!("{base}/v1/blocks/{data_cid_str}"),
            cert: format!("{base}/v1/blocks/{cert_cid_str}"),
            jsonld: format!("{base}/v1/blocks/{cert_cid_str}?as=jsonld"),
            vc: format!("{base}/v1/blocks/{cert_cid_str}?as=vc"),
        },
    };

    let mut resp = (StatusCode::CREATED, Json(response_body)).into_response();
    // The response is a JSON-LD 1.1 document — W3C/IANA mandate application/ld+json.
    // Browsers and HTTP clients treat it as JSON; OpenAI agents parse it correctly.
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, "application/ld+json".parse().unwrap());
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        CACHE_CONTROL_CERTIFY.parse().unwrap(),
    );
    // ETag matches @id (data CID = primary resource identifier).
    resp.headers_mut()
        .insert(header::ETAG, format!("\"{data_cid_str}\"").parse().unwrap());
    // v0.4.0 T5: loud-but-permissive signal to callers that sent an
    // unknown (or absent) Content-Type and therefore got the raw-bytes
    // codec path by default.
    if emit_warning_header {
        resp.headers_mut().insert(
            "warning",
            "299 - \"content-type treated as opaque bytes\""
                .parse()
                .unwrap(),
        );
    }
    Ok(resp)
}

/// Query-string parameters on `GET /v1/blocks/{cid}` — v0.3.0 adds `as=…`.
#[derive(Debug, Deserialize)]
pub struct BlockQuery {
    /// One of `"raw"` (default), `"jsonld"`, `"vc"`.
    #[serde(rename = "as")]
    pub as_: Option<String>,
}

async fn block_handler(
    State(state): State<ServiceState>,
    Path(cid_str): Path<String>,
    Query(q): Query<BlockQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cid = Cid::try_from(cid_str.as_str()).map_err(|_| ApiError::BadRequest {
        error: "malformed CID",
        detail: format!("`{cid_str}` is not a valid CID v1"),
    })?;

    let bytes = state
        .store
        .get(&cid)
        .await
        .map_err(map_store_err)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "the CID `{cid_str}` is well-formed but no block with this CID \
                 exists on this server; it may have been produced by a different \
                 instance or evicted"
            ))
        })?;

    // v0.3.0 — projection dispatch. Precedence: explicit `?as=` wins
    // over Accept negotiation, because it's the explicit opt-in.
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want = match q.as_.as_deref() {
        Some("jsonld") => Projection::JsonLd,
        Some("vc") => Projection::Vc,
        Some("raw") | None => match accept {
            a if a.contains("application/vc+ld+json") => Projection::Vc,
            a if a.contains("application/ld+json") => Projection::JsonLd,
            _ => Projection::Raw,
        },
        Some(other) => {
            return Err(ApiError::BadRequest {
                error: "unsupported projection",
                detail: format!("?as=`{other}` is not supported; use raw, jsonld, or vc"),
            });
        }
    };

    match want {
        Projection::Raw => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                "application/vnd.ipld.raw".parse().unwrap(),
            );
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, CACHE_CONTROL_BLOCK.parse().unwrap());
            resp.headers_mut()
                .insert(header::ETAG, format!("\"{cid_str}\"").parse().unwrap());
            Ok(resp)
        }
        Projection::JsonLd => {
            let cert = projection::assert_cert_block(&bytes).map_err(|_| {
                ApiError::NotAcceptable(
                    "JSON-LD projection is only available for UOR certificate blocks",
                )
            })?;
            let v = projection::certificate_block_as_jsonld(&cert, &cid);
            typed_json_response(v, "application/ld+json", &cid_str)
        }
        Projection::Vc => {
            let cert = projection::assert_cert_block(&bytes).map_err(|_| {
                ApiError::NotAcceptable(
                    "VC 2.0 projection is only available for UOR certificate blocks",
                )
            })?;
            let vc = projection::certificate_block_as_vc(&cert, &cid, state.signing.as_ref())
                .map_err(|e| ApiError::Internal(format!("vc sign: {e}")))?;
            typed_json_response(vc, "application/vc+ld+json", &cid_str)
        }
    }
}

/// Render a serde Value as a response body with the given MIME type
/// and the same `immutable` + ETag caching discipline as the raw path
/// — the projection is a pure function of the bytes the CID addresses,
/// so the projected document is just as immutable.
fn typed_json_response(
    value: serde_json::Value,
    content_type: &str,
    cid_str: &str,
) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(&value)
        .map_err(|e| ApiError::Internal(format!("serialize projection: {e}")))?;
    let mut resp = Response::new(axum::body::Body::from(body));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, CACHE_CONTROL_BLOCK.parse().unwrap());
    resp.headers_mut()
        .insert(header::ETAG, format!("\"{cid_str}\"").parse().unwrap());
    Ok(resp)
}

/// Internal dispatch on block-GET projections.
enum Projection {
    Raw,
    JsonLd,
    Vc,
}

async fn health_handler(State(state): State<ServiceState>) -> Response {
    match state.store.ping().await {
        Ok(descriptor) => {
            let signing = match &state.signing {
                Some(cfg) => serde_json::json!({
                    "enabled": true,
                    "algorithm": "ed25519",
                    "verification_method": projection::VERIFICATION_METHOD,
                    "public_key_multibase": cfg.public_multikey,
                }),
                None => serde_json::json!({ "enabled": false }),
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "store":  descriptor,
                    "signing": signing,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthDegraded {
                status: "degraded",
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn openapi_handler() -> Response {
    let spec = include_str!("../../../openapi.yaml");
    let mut resp = Response::new(axum::body::Body::from(spec));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, "application/yaml".parse().unwrap());
    resp
}

// ─── AI-agent discovery ───────────────────────────────────────────────────────

/// `GET /.well-known/ai-plugin.json`
///
/// OpenAI GPT Actions / ChatGPT Plugin manifest. Any platform that follows
/// the OpenAI plugin discovery convention (ChatGPT, GPT Actions, and
/// compatible agent frameworks) fetches this URL to register the service
/// as a callable tool.
async fn ai_plugin_handler(State(state): State<ServiceState>, headers: HeaderMap) -> Response {
    let base = derive_base_url(&state, &headers);
    let manifest = serde_json::json!({
        "schema_version": "v1",
        "name_for_human": "UOR Certify",
        "name_for_model": "uor_certify",
        "description_for_human": "Assign a permanent, verifiable identity to any digital object using the UOR kernel and IPFS content-addressing.",
        "description_for_model": "Use this tool to certify any digital object or JSON payload. It runs the object through the UOR ontological kernel (assigning a stable uor_address), stores it content-addressed in IPFS, and returns a tamper-evident identity bundle. The response is a valid JSON-LD document containing: @id (ipfs:// URI — the permanent content address), uor_address (the UOR canonical name), certificate (ipfs:// URI of the admission proof), integrity (SRI-2 sha256 for browser/CDN use), and digestMultibase (W3C Data Integrity 1.0). Call this whenever you need a decentralized, universally verifiable, tamper-evident identifier for any data: documents, AI outputs, configs, model cards, structured records, or arbitrary bytes.",
        "auth": { "type": "none" },
        "api": {
            "type": "openapi",
            "url": format!("{base}/v1/openapi.yaml")
        },
        "logo_url": "https://uor.foundation/favicon.ico",
        "contact_email": "info@uor.foundation",
        "legal_info_url": "https://uor.foundation/"
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(manifest),
    )
        .into_response()
}

/// `GET /v1/openai-tools`
///
/// Returns the OpenAI function-calling schema for every tool this service
/// exposes. Paste the response directly into any OpenAI-compatible agent:
/// LangChain, CrewAI, AutoGPT, AWS Bedrock Agents, or a raw
/// `openai.chat.completions.create(tools=[...])` call.
async fn openai_tools_handler() -> impl IntoResponse {
    Json(serde_json::json!([
        {
            "type": "function",
            "function": {
                "name": "certify_object",
                "description": "Certify any JSON object or digital artifact. Runs it through the UOR ontological kernel to assign a permanent canonical identity (uor_address), stores it content-addressed in IPFS, and returns a tamper-evident JSON-LD identity bundle with @id (ipfs:// URI), uor_address, certificate, integrity (SRI-2), and digestMultibase (W3C Data Integrity 1.0). Use this to create decentralized, verifiable identifiers for AI outputs, documents, datasets, model cards, configs, or any structured data. IMPORTANT: the properties you pass ARE the certified payload — pass your data as top-level keys, not wrapped in a container.",
                "parameters": {
                    "type": "object",
                    "description": "The JSON object to certify. Every key-value pair you include here becomes part of the certified, content-addressed payload. The entire arguments object is POSTed as-is to the certify endpoint.",
                    "additionalProperties": true
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_certified_block",
                "description": "Retrieve a previously certified block by its CID. Use the CID from the @id field (strip the ipfs:// prefix) or certificate field of a prior certify_object response. Supports projection to JSON-LD (append ?as=jsonld) or W3C VC 2.0 (append ?as=vc).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cid": {
                            "type": "string",
                            "description": "The CIDv1 of the block to retrieve (base32 string, e.g. bafyrei…). Obtained from the @id or certificate field of certify_object."
                        },
                        "projection": {
                            "type": "string",
                            "enum": ["raw", "jsonld", "vc"],
                            "description": "Output format. raw = IPLD block bytes (default); jsonld = JSON-LD document; vc = W3C Verifiable Credential 2.0."
                        }
                    },
                    "required": ["cid"]
                }
            }
        }
    ]))
}

// ─── errors ──────────────────────────────────────────────────────────────────

/// Service-level error. v0.2.0 adds `ServiceUnavailable` for the 503
/// the handlers return when the backend is unreachable.
#[derive(Debug)]
pub enum ApiError {
    /// 400 with a stable `error` tag and a free-form `detail`.
    BadRequest {
        /// Stable, machine-parseable tag.
        error: &'static str,
        /// Human-readable explanation.
        detail: String,
    },
    /// 404 — CID is well-formed but nothing stored under it.
    NotFound(String),
    /// 413 — request body exceeded the content-type-specific cap.
    PayloadTooLarge(String),
    /// 500 — kernel, encoding, or unrecoverable backend failure.
    Internal(String),
    /// 503 — backend is transiently unreachable.
    ServiceUnavailable(String),
    /// 406 — caller asked for a projection that does not fit the block
    /// (e.g. JSON-LD projection on a non-cert block).
    NotAcceptable(&'static str),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::BadRequest { error, detail } => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error, "detail": detail })),
            )
                .into_response(),
            ApiError::NotFound(detail) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "block not stored",
                    "detail": detail,
                })),
            )
                .into_response(),
            ApiError::PayloadTooLarge(detail) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "error": "payload too large",
                    "detail": detail,
                })),
            )
                .into_response(),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response(),
            ApiError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response(),
            ApiError::NotAcceptable(msg) => (
                StatusCode::NOT_ACCEPTABLE,
                Json(serde_json::json!({
                    "error": "not acceptable",
                    "detail": msg,
                })),
            )
                .into_response(),
        }
    }
}
