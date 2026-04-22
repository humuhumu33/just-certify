//! Durable block store — v0.2.0.
//!
//! v0.1.x shipped an in-memory `DashMap` behind a variant enum. This
//! module replaces that with a trait + three concrete implementations:
//!
//! | Impl            | Purpose                                           |
//! |-----------------|---------------------------------------------------|
//! | [`MemoryStore`] | Tests and explicit `SEM_IPLD_STORE=memory` only.  |
//! | [`KuboStore`]   | **Default.** Talks to a local Kubo daemon via its HTTP RPC. Pins every `put`. |
//! | [`CachedStore`] | LRU wrapper over any [`BlockStore`]. Default capacity 10 000 entries. |
//!
//! The v0.2.0 `KuboStore` call to `/api/v0/block/get` always sets
//! `offline=true` — sem-ipld is a durable *local* store, not a
//! network-federated IPFS node. With `offline=true`, a missing block
//! returns a deterministic 500 JSON error immediately (no DHT wait),
//! which this module maps to `Ok(None)`.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cid::Cid;
use dashmap::DashMap;
use lru::LruCache;
use thiserror::Error;

// ─── error type ─────────────────────────────────────────────────────────────

/// Store-level error.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend cannot be contacted (network error, ping timeout, etc.).
    /// Handlers MUST map this to HTTP 503.
    #[error("backend unreachable: {0}")]
    Unreachable(String),

    /// Backend returned a CID that does not equal the one we computed.
    /// Violates the content-addressing invariant — indicates a bug in
    /// either sem-ipld's CID computation or the backend's. Handlers
    /// MUST map this to HTTP 500 and log at ERROR.
    #[error("cid mismatch: store returned {got}, expected {expected}")]
    CidMismatch {
        /// The CID sem-ipld computed for the bytes.
        expected: Cid,
        /// The CID the backend claimed for the same bytes.
        got: Cid,
    },

    /// Any other backend-level error — non-2xx response, JSON parse
    /// failure on the RPC body, etc. Handlers MUST map to HTTP 500.
    #[error("backend error: {0}")]
    Backend(String),
}

// ─── the trait ──────────────────────────────────────────────────────────────

/// The durable-block-store surface. Every v0.2.0 handler speaks only
/// to this trait; no concrete store type appears in the handler code.
#[async_trait]
pub trait BlockStore: Send + Sync + 'static {
    /// Idempotently store `bytes` under `cid`. Storing the same CID
    /// twice is a no-op at the backend (Kubo short-circuits) and
    /// MUST be at the trait level too.
    async fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError>;

    /// Retrieve bytes for `cid`. Returns:
    /// * `Ok(Some(bytes))` on hit.
    /// * `Ok(None)` on clean miss (CID parses fine; backend does not have it).
    /// * `Err(StoreError)` on backend failure.
    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError>;

    /// Cheap backend-liveness check. Used by `/v1/health` and by the
    /// startup fail-fast gate.
    ///
    /// Returns a short backend-description string on success (e.g.
    /// `"kubo 0.30.0"`, `"memory"`) — the health handler exposes this
    /// in its response body.
    async fn ping(&self) -> Result<String, StoreError>;
}

// ─── MemoryStore ────────────────────────────────────────────────────────────

/// In-memory block store backed by `DashMap`. **Not durable** —
/// retained for unit tests and the explicit `SEM_IPLD_STORE=memory`
/// invocation. The v0.1.x default; no longer the v0.2.0 default.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<DashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// Fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlockStore for MemoryStore {
    async fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError> {
        self.inner
            .entry(cid.to_string())
            .or_insert_with(|| bytes.to_vec());
        Ok(())
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.inner.get(&cid.to_string()).map(|r| r.clone()))
    }

    async fn ping(&self) -> Result<String, StoreError> {
        Ok("memory".into())
    }
}

// ─── KuboStore ──────────────────────────────────────────────────────────────

/// Durable block store backed by a local Kubo daemon.
///
/// Every `put` includes `pin=true` in the RPC call — Kubo's garbage
/// collector will not touch our blocks. Every `get` includes
/// `offline=true` — Kubo does not attempt DHT lookups for missing
/// blocks, so misses return immediately rather than blocking.
#[derive(Clone)]
pub struct KuboStore {
    client: reqwest::Client,
    api_url: String,
}

impl KuboStore {
    /// Construct a client against `api_url` (e.g. `"http://127.0.0.1:5001"`)
    /// with the given per-call timeout.
    #[must_use]
    pub fn new(api_url: impl Into<String>, timeout: std::time::Duration) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("reqwest client builds"),
            api_url: api_url.into().trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl BlockStore for KuboStore {
    async fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError> {
        // Codec name Kubo expects — derived from the CID itself.
        let codec_name = match cid.codec() {
            0x71 => "dag-cbor",
            0x55 => "raw",
            0x0129 => "dag-json",
            c => return Err(StoreError::Backend(format!("unsupported codec 0x{c:x}"))),
        };
        let url = format!(
            "{}/api/v0/block/put?cid-codec={codec_name}&mhtype=sha2-256&mhlen=32&cid-version=1&pin=true",
            self.api_url
        );

        // The `data` multipart field carries the raw block bytes.
        let form = reqwest::multipart::Form::new().part(
            "data",
            reqwest::multipart::Part::bytes(bytes.to_vec())
                .file_name("block")
                .mime_str("application/octet-stream")
                .map_err(|e| StoreError::Backend(e.to_string()))?,
        );

        let resp = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| StoreError::Unreachable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(StoreError::Backend(format!("block/put {status}: {body}")));
        }

        #[derive(serde::Deserialize)]
        struct PutResponse {
            #[serde(rename = "Key")]
            key: String,
        }
        let body: PutResponse = resp
            .json()
            .await
            .map_err(|e| StoreError::Backend(format!("block/put JSON: {e}")))?;

        let got: Cid = body
            .key
            .parse()
            .map_err(|e| StoreError::Backend(format!("block/put CID parse: {e}")))?;

        if &got != cid {
            return Err(StoreError::CidMismatch {
                expected: *cid,
                got,
            });
        }
        Ok(())
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        let url = format!("{}/api/v0/block/get?arg={}&offline=true", self.api_url, cid);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StoreError::Unreachable(e.to_string()))?;

        if resp.status().is_success() {
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            return Ok(Some(bytes.to_vec()));
        }

        // Non-2xx. Inspect the error body — Kubo returns a JSON envelope
        // like `{"Message":"block was not found locally (offline): …", …}`
        // for misses; anything else is a real backend error.
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let lower = body.to_lowercase();
        let is_miss = lower.contains("not found locally")
            || lower.contains("blockservice: key not found")
            || lower.contains("ipld: could not find");
        if is_miss {
            Ok(None)
        } else {
            Err(StoreError::Backend(format!("block/get {status}: {body}")))
        }
    }

    async fn ping(&self) -> Result<String, StoreError> {
        let url = format!("{}/api/v0/version", self.api_url);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| StoreError::Unreachable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StoreError::Backend(format!(
                "/api/v0/version {}",
                resp.status()
            )));
        }
        #[derive(serde::Deserialize)]
        struct VersionResponse {
            #[serde(rename = "Version")]
            version: String,
        }
        let v: VersionResponse = resp
            .json()
            .await
            .map_err(|e| StoreError::Backend(format!("/api/v0/version JSON: {e}")))?;
        Ok(format!("kubo {}", v.version))
    }
}

// ─── CachedStore ────────────────────────────────────────────────────────────

/// LRU-cached wrapper over any [`BlockStore`]. Collapses the p50
/// cache-hit latency back under 1 ms and reduces pressure on the
/// Kubo sidecar.
pub struct CachedStore<S: BlockStore> {
    inner: S,
    cache: Mutex<LruCache<Cid, Vec<u8>>>,
}

impl<S: BlockStore> CachedStore<S> {
    /// Wrap `inner` with a fresh LRU of `capacity` entries.
    #[must_use]
    pub fn new(inner: S, capacity: NonZeroUsize) -> Self {
        Self {
            inner,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }
}

#[async_trait]
impl<S: BlockStore> BlockStore for CachedStore<S> {
    async fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError> {
        self.inner.put(cid, bytes).await?;
        // Write-through so subsequent GETs hit the cache.
        let mut cache = self.cache.lock().expect("cache mutex not poisoned");
        cache.put(*cid, bytes.to_vec());
        Ok(())
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        // Scoped lock: release before `.await` on the backend.
        {
            let mut cache = self.cache.lock().expect("cache mutex not poisoned");
            if let Some(v) = cache.get(cid) {
                return Ok(Some(v.clone()));
            }
        }
        let bytes = self.inner.get(cid).await?;
        if let Some(ref b) = bytes {
            let mut cache = self.cache.lock().expect("cache mutex not poisoned");
            cache.put(*cid, b.clone());
        }
        Ok(bytes)
    }

    async fn ping(&self) -> Result<String, StoreError> {
        self.inner.ping().await
    }
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_cid(seed: u8) -> Cid {
        use sem_ipld::hasher::{sha256, CODEC_DAG_CBOR, MULTIHASH_SHA2_256};
        let digest = sha256(&[seed; 32]);
        sem_ipld::ipld::cid_from_sha256(CODEC_DAG_CBOR, &digest).unwrap()
    }

    // Shared call-counting mock — used by CachedStore tests to assert
    // that the cache actually absorbs repeat reads.
    struct CallCountingStore {
        inner: MemoryStore,
        get_calls: Arc<AtomicUsize>,
        put_calls: Arc<AtomicUsize>,
    }
    impl CallCountingStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                get_calls: Arc::new(AtomicUsize::new(0)),
                put_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
        #[allow(dead_code)]
        fn get_count(&self) -> usize {
            self.get_calls.load(Ordering::SeqCst)
        }
        #[allow(dead_code)]
        fn put_count(&self) -> usize {
            self.put_calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl BlockStore for CallCountingStore {
        async fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError> {
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.put(cid, bytes).await
        }
        async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get(cid).await
        }
        async fn ping(&self) -> Result<String, StoreError> {
            self.inner.ping().await
        }
    }

    #[tokio::test]
    async fn memory_store_round_trip() {
        let s = MemoryStore::new();
        let c = test_cid(1);
        assert_eq!(s.get(&c).await.unwrap(), None);
        s.put(&c, b"hello").await.unwrap();
        assert_eq!(s.get(&c).await.unwrap(), Some(b"hello".to_vec()));
        assert_eq!(s.ping().await.unwrap(), "memory");
    }

    #[tokio::test]
    async fn cached_store_absorbs_repeat_reads() {
        // First get() misses cache → inner.get is called.
        // Second get() hits cache → inner.get is NOT called.
        let inner = CallCountingStore::new();
        let get_counter = inner.get_calls.clone();
        let cached = CachedStore::new(inner, NonZeroUsize::new(10).unwrap());
        let c = test_cid(2);
        cached.put(&c, b"cached").await.unwrap();

        // First read (may be a cache hit from write-through).
        let v = cached.get(&c).await.unwrap();
        assert_eq!(v, Some(b"cached".to_vec()));
        // Second read — cache hit; inner.get should NOT be called.
        let before = get_counter.load(Ordering::SeqCst);
        let v2 = cached.get(&c).await.unwrap();
        assert_eq!(v2, Some(b"cached".to_vec()));
        let after = get_counter.load(Ordering::SeqCst);
        assert_eq!(before, after, "cache failed to absorb repeat read");
    }

    #[tokio::test]
    async fn cached_store_writes_through_on_put() {
        let inner = CallCountingStore::new();
        let put_counter = inner.put_calls.clone();
        let cached = CachedStore::new(inner, NonZeroUsize::new(10).unwrap());
        let c = test_cid(3);
        cached.put(&c, b"wt").await.unwrap();
        assert_eq!(
            put_counter.load(Ordering::SeqCst),
            1,
            "put must write through to inner"
        );
    }

    #[tokio::test]
    async fn cached_store_evicts_past_capacity() {
        // Capacity 2. Put 3 distinct CIDs. The oldest should evict;
        // the inner store still has it, but the cache no longer does,
        // so a get() of the evicted CID incurs an inner.get call.
        let inner = CallCountingStore::new();
        let get_counter = inner.get_calls.clone();
        let cached = CachedStore::new(inner, NonZeroUsize::new(2).unwrap());
        let c1 = test_cid(10);
        let c2 = test_cid(11);
        let c3 = test_cid(12);
        cached.put(&c1, b"one").await.unwrap();
        cached.put(&c2, b"two").await.unwrap();
        cached.put(&c3, b"three").await.unwrap(); // evicts c1

        let before = get_counter.load(Ordering::SeqCst);
        // c2 / c3 are still cached.
        let _ = cached.get(&c2).await.unwrap();
        let _ = cached.get(&c3).await.unwrap();
        let after_hits = get_counter.load(Ordering::SeqCst);
        assert_eq!(after_hits, before, "c2 / c3 should hit cache");

        // c1 evicted — reads through to inner.
        let _ = cached.get(&c1).await.unwrap();
        let after_miss = get_counter.load(Ordering::SeqCst);
        assert!(after_miss > after_hits, "evicted c1 must miss cache");
    }
}
