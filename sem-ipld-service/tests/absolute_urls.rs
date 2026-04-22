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
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn urls_use_host_header_when_no_proxy() {
    let body = call_certify(fresh_state(), &[("host", "sem.example:9000")]).await;
    let data_url = body["urls"]["data"].as_str().unwrap();
    assert!(data_url.starts_with("http://sem.example:9000/v1/blocks/"), "got {data_url}");
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
    let data_url = body["urls"]["data"].as_str().unwrap();
    assert!(data_url.starts_with("https://api.uor.foundation/v1/blocks/"), "got {data_url}");
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
    let data_url = body["urls"]["data"].as_str().unwrap();
    assert!(data_url.starts_with("https://cdn.example.com/v1/blocks/"), "got {data_url}");
    assert!(!data_url.contains("evil.example"));
    assert!(!data_url.contains("origin.internal"));
}

#[tokio::test]
async fn idempotency_preserved_through_store() {
    let state = fresh_state();
    let a = call_certify(state.clone(), &[("host", "localhost")]).await;
    let b = call_certify(state, &[("host", "localhost")]).await;
    assert_eq!(a["data_cid"], b["data_cid"]);
    assert_eq!(a["certificate_cid"], b["certificate_cid"]);
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
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1 << 20).await.unwrap();
    let post_body: Value = serde_json::from_slice(&post_bytes).unwrap();
    let data_cid = post_body["data_cid"].as_str().unwrap();

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
    assert_eq!(cache, "public, max-age=31536000, immutable",
        "v0.2.0 must restore the immutable directive on block-GET");
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
    let cache = resp.headers().get("cache-control").unwrap().to_str().unwrap();
    assert_eq!(cache, "public, max-age=300, must-revalidate");
    assert!(!cache.contains("immutable"));
}
