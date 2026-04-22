//! v0.1.x regression test kept in v0.2.0: URLs must remain absolute
//! under the new `Arc<dyn BlockStore>` state shape. Uses `MemoryStore`
//! so the test is self-contained (no Kubo required).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sem_ipld_service::{router, BlockStore, MemoryStore, ServiceState};
use serde_json::Value;
use tower::ServiceExt;

fn fresh_state() -> ServiceState {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    ServiceState::new(store).unwrap()
}

async fn call_certify(state: ServiceState, extra_headers: &[(&str, &str)]) -> Value {
    let app = router(state);
    let mut req_builder = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json");
    for (k, v) in extra_headers {
        req_builder = req_builder.header(*k, *v);
    }
    let req = req_builder.body(Body::from(r#"{"v":1}"#)).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn urls_use_host_header_when_no_proxy() {
    let body = call_certify(fresh_state(), &[("host", "sem.example:9000")]).await;
    let data_url = body["gateway"]["data"].as_str().unwrap();
    assert!(
        data_url.starts_with("http://sem.example:9000/v1/blocks/"),
        "got {data_url}"
    );
}

#[tokio::test]
async fn urls_respect_x_forwarded_headers() {
    let body = call_certify(
        fresh_state(),
        &[
            ("host", "origin.internal"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "api.uor.foundation"),
        ],
    )
    .await;
    let data_url = body["gateway"]["data"].as_str().unwrap();
    assert!(
        data_url.starts_with("https://api.uor.foundation/v1/blocks/"),
        "got {data_url}"
    );
    assert!(!data_url.contains("origin.internal"));
}

#[tokio::test]
async fn public_base_url_override_wins() {
    let mut state = fresh_state();
    state.public_base_url = Some("https://cdn.example.com".into());
    let body = call_certify(
        state,
        &[
            ("host", "origin.internal"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "evil.example"),
        ],
    )
    .await;
    let data_url = body["gateway"]["data"].as_str().unwrap();
    assert!(
        data_url.starts_with("https://cdn.example.com/v1/blocks/"),
        "got {data_url}"
    );
    assert!(!data_url.contains("evil.example"));
    assert!(!data_url.contains("origin.internal"));
}

#[tokio::test]
async fn idempotency_preserved_through_store() {
    let state = fresh_state();
    let a = call_certify(state.clone(), &[("host", "localhost")]).await;
    let b = call_certify(state, &[("host", "localhost")]).await;
    // @id = ipfs://<data_cid> and certificate = ipfs://<cert_cid> — both stable
    assert_eq!(a["@id"], b["@id"]);
    assert_eq!(a["certificate"], b["certificate"]);
}

/// v0.2.0: block-GET must carry the restored `immutable` directive.
#[tokio::test]
async fn block_get_carries_immutable_cache_header() {
    let state = fresh_state();
    let app = router(state);

    // Publish something first, then GET the CID.
    let post = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(r#"{"v":42}"#))
        .unwrap();
    let post_resp = app.clone().oneshot(post).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::CREATED);
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let post_body: Value = serde_json::from_slice(&post_bytes).unwrap();
    // @id is now "ipfs://<data_cid>" — strip the scheme prefix
    let data_cid = post_body["@id"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap();

    let get = Request::builder()
        .method("GET")
        .uri(format!("/v1/blocks/{data_cid}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let cache = get_resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        cache, "public, max-age=31536000, immutable",
        "v0.2.0 must restore the immutable directive on block-GET"
    );
}

/// v0.2.0: certify-POST cache header stays at max-age=300 must-revalidate.
#[tokio::test]
async fn certify_post_cache_header_is_not_immutable() {
    let state = fresh_state();
    let app = router(state);
    let post = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(r#"{"v":7}"#))
        .unwrap();
    let resp = app.oneshot(post).await.unwrap();
    let cache = resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cache, "public, max-age=300, must-revalidate");
    assert!(!cache.contains("immutable"));
}

// ─── uor_address fix verification ────────────────────────────────────────────

async fn certify_json(state: ServiceState, json: &'static str) -> Value {
    let app = router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/certify")
        .header("content-type", "application/json")
        .header("host", "localhost")
        .body(Body::from(json))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// TEST 1 fix: uor_address must differ for different payloads.
#[tokio::test]
async fn uor_address_differs_across_payloads() {
    let a = certify_json(fresh_state(), r#"{"fn":"iterative","var":"seq"}"#).await;
    let b = certify_json(fresh_state(), r#"{"fn":"iterative","var":"buf"}"#).await;
    let c = certify_json(fresh_state(), r#"{"fn":"recursive","algo":"different"}"#).await;

    let ua = a["uor_address"].as_str().unwrap();
    let ub = b["uor_address"].as_str().unwrap();
    let uc = c["uor_address"].as_str().unwrap();

    assert_ne!(ua, ub, "different payloads must produce different uor_address");
    assert_ne!(ua, uc, "different payloads must produce different uor_address");
    assert_ne!(ub, uc, "different payloads must produce different uor_address");

    // @id must also differ (pre-existing guarantee)
    assert_ne!(a["@id"], b["@id"]);
    assert_ne!(a["@id"], c["@id"]);
}

/// TEST 2 fix: uor_address must change on any byte-level change.
#[tokio::test]
async fn uor_address_changes_on_any_mutation() {
    let base  = certify_json(fresh_state(), r#"{"source":"def f(): pass"}"#).await;
    let newline = certify_json(fresh_state(), r#"{"source":"def f(): pass\n"}"#).await;
    let comment = certify_json(fresh_state(), r#"{"source":"def f(): pass # hi"}"#).await;

    let u0 = base["uor_address"].as_str().unwrap();
    assert_ne!(u0, newline["uor_address"].as_str().unwrap(), "newline must change uor_address");
    assert_ne!(u0, comment["uor_address"].as_str().unwrap(), "comment must change uor_address");
}

/// TEST 4 fix: uor_address must be identical for identical payloads (idempotency).
#[tokio::test]
async fn uor_address_is_idempotent() {
    let state = fresh_state();
    let a = certify_json(state.clone(), r#"{"payload":"same","n":42}"#).await;
    let b = certify_json(state.clone(), r#"{"payload":"same","n":42}"#).await;
    let c = certify_json(state,         r#"{"payload":"same","n":42}"#).await;

    assert_eq!(a["uor_address"], b["uor_address"], "idempotency: call A == call B");
    assert_eq!(b["uor_address"], c["uor_address"], "idempotency: call B == call C");
    assert_eq!(a["@id"], b["@id"]);
    assert_eq!(b["@id"], c["@id"]);
}

/// uor_address must never be the old constant `z9Yrf1azdEyiEQdkaPpk4wc`.
#[tokio::test]
async fn uor_address_is_not_the_old_constant() {
    let old_constant = "z9Yrf1azdEyiEQdkaPpk4wc";
    for json in [r#"{"v":1}"#, r#"{"fn":"fib"}"#, r#"{"x":"y"}"#] {
        let body = certify_json(fresh_state(), json).await;
        assert_ne!(
            body["uor_address"].as_str().unwrap(),
            old_constant,
            "uor_address must not be the old constant for payload {json}"
        );
    }
}
