//! Binary entry point — v0.2.0.
//!
//! Fail-fast discipline: the service does NOT bind its HTTP listener
//! until the chosen block store responds to `ping()`. A running
//! service that silently returns 503 on every request because its
//! Kubo sidecar is down is worse than a service that refuses to
//! start — the former silently violates the `Cache-Control: immutable`
//! contract under partial failure.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use sem_ipld_service::{
    router, BlockStore, CachedStore, KuboStore, MemoryStore, ServiceState, SigningConfig,
};

/// Resolved configuration read from env vars.
struct Config {
    store_kind: StoreKind,
    ipfs_api_url: String,
    ipfs_timeout: Duration,
    lru_capacity: NonZeroUsize,
    bind_addr: std::net::SocketAddr,
    public_base_url: Option<String>,
}

enum StoreKind {
    Kubo,
    Memory,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let store_kind = match std::env::var("SEM_IPLD_STORE")
            .unwrap_or_else(|_| "kubo".into())
            .as_str()
        {
            "kubo" => StoreKind::Kubo,
            "memory" => StoreKind::Memory,
            other => {
                return Err(format!(
                    "SEM_IPLD_STORE must be `kubo` or `memory`, got `{other}`"
                )
                .into())
            }
        };
        let ipfs_api_url = std::env::var("SEM_IPLD_IPFS_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:5001".into());
        let ipfs_timeout_ms: u64 = std::env::var("SEM_IPLD_IPFS_TIMEOUT_MS")
            .unwrap_or_else(|_| "5000".into())
            .parse()?;
        let lru_capacity: usize = std::env::var("SEM_IPLD_LRU_CAPACITY")
            .unwrap_or_else(|_| "10000".into())
            .parse()?;
        let lru_capacity = NonZeroUsize::new(lru_capacity)
            .ok_or("SEM_IPLD_LRU_CAPACITY must be > 0")?;
        let bind = std::env::var("SEM_IPLD_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8787".into());
        let bind_addr: std::net::SocketAddr = bind.parse()?;
        let public_base_url = std::env::var("PUBLIC_BASE_URL").ok();

        Ok(Self {
            store_kind,
            ipfs_api_url,
            ipfs_timeout: Duration::from_millis(ipfs_timeout_ms),
            lru_capacity,
            bind_addr,
            public_base_url,
        })
    }

    fn store_label(&self) -> String {
        match self.store_kind {
            StoreKind::Kubo => format!("kubo @ {}", self.ipfs_api_url),
            StoreKind::Memory => "memory (ephemeral — tests only)".into(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sem_ipld_service=info,tower_http=info".into()),
        )
        .init();

    let cfg = Config::from_env()?;

    tracing::info!(
        store = %cfg.store_label(),
        ipfs_timeout_ms = cfg.ipfs_timeout.as_millis() as u64,
        lru_capacity = cfg.lru_capacity.get(),
        bind = %cfg.bind_addr,
        public_base_url = ?cfg.public_base_url,
        "sem-ipld-service starting"
    );

    // Build the chosen store behind the `BlockStore` trait.
    let store: Arc<dyn BlockStore> = match cfg.store_kind {
        StoreKind::Kubo => {
            let kubo = KuboStore::new(cfg.ipfs_api_url.clone(), cfg.ipfs_timeout);
            let cached = CachedStore::new(kubo, cfg.lru_capacity);
            Arc::new(cached)
        }
        StoreKind::Memory => Arc::new(MemoryStore::new()),
    };

    // Fail-fast gate: ping the store before we bind the listener.
    match store.ping().await {
        Ok(descriptor) => {
            tracing::info!(backend = %descriptor, "store ping OK");
        }
        Err(e) => {
            tracing::error!(error = %e, "store ping FAILED; refusing to start");
            eprintln!("sem-ipld-service: store unreachable — {e}");
            std::process::exit(1);
        }
    }

    // v0.4.0 — parse SEM_IPLD_ISSUER_KEY_B64 into a SigningConfig, if
    // present. Fail fast with a clear error on malformed key material;
    // never silently fall back to unsigned.
    let signing = match std::env::var("SEM_IPLD_ISSUER_KEY_B64") {
        Ok(ref s) if !s.is_empty() => match SigningConfig::from_base64_seed(s) {
            Ok(cfg) => {
                tracing::info!(
                    public_key_multibase = %cfg.public_multikey,
                    "signing enabled (uor-dag-cbor-ed25519-2025)"
                );
                Some(cfg)
            }
            Err(e) => {
                tracing::error!(error = %e, "invalid SEM_IPLD_ISSUER_KEY_B64; refusing to start");
                eprintln!("sem-ipld-service: invalid signing key — {e}");
                std::process::exit(1);
            }
        },
        _ => {
            tracing::info!("signing disabled (SEM_IPLD_ISSUER_KEY_B64 unset; uor-dag-cbor-2025)");
            None
        }
    };

    let state = ServiceState {
        context: sem_ipld::context::SemanticContext::with_bytes(
            sem_ipld::context::SemanticContext::CANONICAL_IRI,
            sem_ipld_service::DEFAULT_CONTEXT_BYTES,
        )?,
        store,
        public_base_url: cfg.public_base_url,
        signing,
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(
        "sem-ipld-service listening on http://{}\n  \
         POST /v1/certify         — run UOR admission, publish block pair\n  \
         GET  /v1/blocks/{{cid}}    — IPIP-402 raw block bytes (immutable)\n  \
         GET  /v1/health          — liveness + store descriptor\n  \
         GET  /v1/openapi.yaml    — API spec",
        cfg.bind_addr,
    );
    axum::serve(listener, app).await?;
    Ok(())
}
