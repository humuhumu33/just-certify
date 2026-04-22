# Changelog

## 0.4.0 — Signed cryptosuite, DID publication, spec completeness

Additive release driven by the v0.3.0 external bottle-test audit.
No breaking changes. Every v0.3.0 client keeps working identically.

### Why

The v0.3.0 bottle-test reviewer independently characterized
`uor-dag-cbor-2025` as a *"tamper-evidence cryptosuite, not a
signature cryptosuite"* — "the cheapest honest witness you can
compute for a document." Accurate and load-bearing: it names
both the scope and the scenarios the unsigned variant does not
serve (EUDI wallets, multi-party legal-tech credential networks,
Solid user-asserted claims, any workflow where authenticity
matters).

v0.4.0 ships the signed variant alongside the unsigned one,
completes the OpenAPI spec, and publishes the cryptosuite
specification document.

### What

- **`uor-vc-crypto` v0.2.0** — adds `uor-dag-cbor-ed25519-2025`:
  same DAG-CBOR canonicalization, Ed25519 signature over the
  34-byte multihash of the CID. Shared `canonicalize_for_proof`
  ensures both variants produce byte-identical canonical bytes
  for the same `(document, common_options)`. New `verify()`
  dispatcher routes on `proof.cryptosuite`. New
  `gen-issuer-key` binary prints a base64 private seed + the
  `z6Mk…` public Multikey. `verify_signed_smoke_test` resolves
  the public key via the running service's `/v1/health` and
  verifies VCs end-to-end.
- **`sem-ipld-service` v0.4.0** — conditional signing. When the
  `SEM_IPLD_ISSUER_KEY_B64` env var is set, `GET /v1/blocks/{cid}?as=vc`
  emits `uor-dag-cbor-ed25519-2025` proofs; when unset, emits the
  v0.3.0 unsigned variant. Service refuses to start on malformed
  key material — no silent fallback. `/v1/health` now carries a
  `signing` block exposing `enabled`, `algorithm`,
  `verification_method`, and `public_key_multibase`.
- **`docs/did/did.json`** now carries a real Ed25519 multikey
  (`z6MkqvwTWf1v7Tmp9HDHM5j6JurtJLhfiiYcPFuyhVVXsqVc` — a demo
  key committed to git; operators replace with their own before
  production). `docs/did/README.md` documents the hosting
  checklist + the operator-side generate-paste-publish flow.
- **OpenAPI completeness sweep** — `digestMultibase`, `urls.jsonld`,
  `urls.vc`, both cryptosuite names, 406 and 503 response codes,
  the `signing` health block, and the Content-Type negotiation
  table are all documented. `grep -cE` of the listed terms
  returns 33 matches.
- **Warning header on unknown Content-Type** — RFC 7234
  `Warning: 299` attached to POST responses when the caller sent
  a Content-Type that is neither `application/json` nor
  `application/vnd.ipld.dag-cbor`. Behavior preserved (still
  routed to raw-bytes), signal is now loud.
- **Opaque-bytes → verifiable VC invariant tests** in
  `tests/vc_projection.rs` (Kubo-gated). Proves the cryptosuite
  is agnostic to the data-block codec; a PDF's cert block
  produces an equally valid VC as a JSON payload's cert block.
- **Cryptosuite specification document** at
  `docs/specs/uor-dag-cbor-2025.md`. ~5,000 words, 12 sections,
  3 test vectors. W3C-style (BBS v1.0 template). Cites the
  round-3 bottle-test reviewer's "tamper-evidence" framing in
  §1.1, §1.2, and §10. Ready for hosting at
  `https://uor.foundation/specs/uor-dag-cbor-2025/` and
  subsequent registration PR to `w3c/vc-extensions`.

### Breaking?

**No.** `POST /v1/certify` request and response shapes are
unchanged modulo the additive `digestMultibase` and `urls.{jsonld,vc}`
fields from v0.3.0. `GET /v1/blocks/{cid}` behaviour is unchanged
modulo the new `?as=` query parameter from v0.3.0. A strict
v0.2.0 client that did not pin response-body keys still parses
v0.4.0 responses.

New env var: `SEM_IPLD_ISSUER_KEY_B64` (optional). Absence of
the var is the v0.3.0 behaviour (unsigned cryptosuite).

### Deliberately not done in v0.4.0

- No spec document for `uor-dag-cbor-ed25519-2025` yet — the
  unsigned variant has external validation (bottle test); the
  signed variant will benefit from its own review cycle before
  a formal spec is written.
- No W3C registration PR. Requires the spec hosted at a stable URL.
- No `@digitalbazaar/vc` plugin adapter. v0.5.0 scope.
- No second signing algorithm. Ed25519 only for v0.4.0.
- No in-service DID resolution. Callers resolve `verificationMethod`
  themselves (or use `verify_signed_smoke_test`'s health-endpoint shim).
- No key rotation, multiple keys, key agility. Post-v1.0 scope.

## 0.3.0 — W3C Semantic Web alignment via Data Integrity cryptosuite

Additive release. No existing `POST /v1/certify` or
`GET /v1/blocks/{cid}` caller changes behavior.

### Why

On 15 May 2025, W3C published two Recommendations that together
define the modern credentials stack: **VC Data Model 2.0** (the
canonical shape for verifiable credentials) and **Data Integrity 1.0**
(the canonical mechanism for attaching cryptographic proofs to
JSON-LD documents). Data Integrity 1.0 formally pulls multihash +
multibase — the content-addressing primitives sem-ipld is built on —
into the W3C stack as first-class proof encoding. The substrate was
already aligned; what was missing was a cryptosuite that binds UOR
cert blocks to VC proofs.

v0.3.0 ships that cryptosuite (`uor-dag-cbor-2025`) as a sibling
crate and exposes two new projection endpoints. After this release,
any W3C VC 2.0 verifier on earth can verify a UOR certificate with
~80 LOC of adapter code and nothing else.

### What

- **New crate `uor-vc-crypto` v0.1.0.** Implements the Data
  Integrity 1.0 cryptosuite `uor-dag-cbor-2025`. Canonicalization
  via `serde_ipld_dagcbor`; `proofValue` is a CIDv1(dag-cbor,
  sha2-256) of the canonical form minus the proofValue itself.
  Unsigned — CID-as-proof gives content-addressed integrity. Signed
  variant (`uor-dag-cbor-ed25519-2025`) is a later release.
- **`digestMultibase` field on `POST /v1/certify` response** — the
  same SHA-256 digest as the SRI `integrity` value, re-encoded as
  `u<base64url multibase-multihash>` (the Data Integrity 1.0 shape).
- **`GET /v1/blocks/{cid}?as=jsonld`** — JSON-LD projection of a
  cert block with multibase-encoded byte fields and `ipfs://` CID
  URIs. Content-Type `application/ld+json`.
- **`GET /v1/blocks/{cid}?as=vc`** — signed VC 2.0 credential
  projection. Issuer `did:web:uor.foundation`, verification method
  `did:web:uor.foundation#key-1`, cryptosuite `uor-dag-cbor-2025`.
  Content-Type `application/vc+ld+json`.
- **Extended `urls` object on certify response** with `jsonld` and
  `vc` URLs alongside the existing `data` / `cert`.
- **`docs/did/did.json`** placeholder + a `README.md` explaining
  the hosting requirement at
  `https://uor.foundation/.well-known/did.json`.

### Breaking?

**No.** Every existing caller keeps working. The response gains
additional optional fields; a strict deserializer that was pinned
to the v0.2.0 shape still parses v0.3.0 responses correctly.

### Follow-on work

- Write the `uor-dag-cbor-2025` spec document (~30–50 pages
  following the BBS v1.0 template) and host it at
  `https://uor.foundation/specs/uor-dag-cbor-2025/`.
- File the registration PR against
  [`w3c/vc-extensions`](https://github.com/w3c/vc-extensions) once
  the spec document is live.
- Upstream integration in `vc-js` / `didkit` — probably via the
  custom-verifier-function extension point so the suite works
  without runtime changes on those projects' parts.
- Ship `uor-dag-cbor-ed25519-2025` as a signed cryptosuite variant
  for federated deployments.
- Publish a real Ed25519 multikey in `did.json`.

## 0.2.0 — Durable block store (local Kubo sidecar)

The release that restores `Cache-Control: immutable` honestly.

### Why

v0.1.0's external audit identified one go/no-go blocker for production:
the service emitted `Cache-Control: immutable` on block reads while
the backing store was an in-memory `DashMap`. Any downstream CDN or
browser cache that honored `immutable` would serve stale URLs that
resolved to 404 after the service restarted. v0.1.1 fixed the
contradiction by *weakening* the cache header to `max-age=300,
must-revalidate`. v0.2.0 fixes it by *strengthening the store* — the
`immutable` directive is now accurate because the backing bytes
survive service restart.

### What changed

- **New `BlockStore` trait** (`#[async_trait]`): `put`, `get`, `ping`.
  Explicit `StoreError` enum via `thiserror` with three variants:
  `Unreachable` → HTTP 503, `CidMismatch` → HTTP 500 + ERROR log,
  `Backend` → HTTP 500.
- **`KuboStore` (new, default)** — talks to a local Kubo daemon via
  its HTTP RPC at `/api/v0/block/put` (with `pin=true`) and
  `/api/v0/block/get` (with `offline=true` so missing blocks return
  a deterministic 500 JSON envelope instead of hanging on DHT
  lookups). Every `put` response has its returned CID compared
  against the CID sem-ipld computed; any mismatch is a hard
  `StoreError::CidMismatch`.
- **`MemoryStore` (retained)** — the old `DashMap` impl now lives
  behind the trait. Use `SEM_IPLD_STORE=memory` in tests or for
  explicit ephemeral demos.
- **`CachedStore<S>`** — LRU wrapper in front of any `BlockStore`,
  default capacity 10 000 entries. Restores the v0.1.0 p50
  cache-hit latency profile and reduces pressure on the Kubo sidecar.
- **Fail-fast startup**: `main.rs` now calls `store.ping().await`
  before binding the HTTP listener. A failed ping logs ERROR and
  `exit(1)`. The orchestrator (systemd / Kubernetes / docker-compose /
  Railway) is the one that decides when to retry.
- **Enhanced `/v1/health`**: returns 200 with `{"status":"ok","store":"kubo 0.30.0"}`
  on success; 503 with `{"status":"degraded","error":"…"}` on ping
  failure. The health probe is now meaningful for liveness checks.
- **`Cache-Control: public, max-age=31536000, immutable` restored**
  on `GET /v1/blocks/{cid}`. `POST /v1/certify` stays at
  `max-age=300, must-revalidate` because its response body embeds
  `urls.data` / `urls.cert` that can change across deployments.

### Breaking changes

None at the HTTP API surface. The request/response shapes on both
endpoints are unchanged from v0.1.1. The OpenAPI spec is unchanged
apart from the `Cache-Control` example values.

**New env vars** (all optional with sane defaults):

| Variable                    | Default                   | Purpose |
|-----------------------------|---------------------------|---------|
| `SEM_IPLD_STORE`            | `kubo`                    | `kubo` or `memory`. |
| `SEM_IPLD_IPFS_API_URL`     | `http://127.0.0.1:5001`   | Kubo RPC endpoint. |
| `SEM_IPLD_IPFS_TIMEOUT_MS`  | `5000`                    | Per-call timeout against Kubo. |
| `SEM_IPLD_LRU_CAPACITY`     | `10000`                   | LRU cache entries. |
| `SEM_IPLD_BIND`             | `127.0.0.1:8787`          | Bind address. |
| `PUBLIC_BASE_URL`           | (none)                    | Unchanged from v0.1.1. |

### Tests

- 6 existing unit/integration tests from v0.1.x still pass.
- 4 new unit tests in `src/store.rs`: MemoryStore round-trip,
  CachedStore absorbs repeat reads, CachedStore writes through on
  put, CachedStore evicts past capacity.
- 3 new Kubo-gated integration tests in `tests/kubo_integration.rs`
  (run with `SEM_IPLD_INTEGRATION=1 cargo test -- --ignored`):
  **put → restart → get still works** (the acceptance gate —
  durability proven across process boundary), **Kubo-down produces
  503 not 500** (adversarial transport), **CID mismatch is a hard
  500** (integrity invariant).
- 2 new cache-header regression tests in `tests/absolute_urls.rs`:
  block-GET carries `immutable`, certify-POST does not.

### Deliberately not done in v0.2.0

- No pinning-service (Pinata / web3.storage) integration. Local Kubo only.
- No embedded Iroh / rust-ipfs. Sidecar only.
- No IPNS, pubsub, DHT publishing, or peer-network exposure.
- No authentication, rate limiting, or multi-tenancy.
- No new HTTP endpoints. Two verbs remain two verbs.
- No semantic normalization (URDNA2015 / JCS). Babel Fish scope
  stays narrow.
- No SQLite / RocksDB / Postgres. Kubo is the store.

## 0.1.1 — External bottle-test audit cycle

Patch release driven by an external audit of the v0.1.0 running service
against eight load-bearing claims. Four surface defects, one
architectural contradiction, and several documentation gaps were
closed. No architecture changes; no new endpoints. See the full audit
at [`reviews/bottle_test_v0.1.0.md`](reviews/bottle_test_v0.1.0.md).

- **FIX 1 — Cache-Control no longer lies.** `immutable` is deliberately
  omitted from both `POST /v1/certify` and `GET /v1/blocks/{cid}`
  responses until a durable store replaces the in-memory `DashMap`;
  the header is now `public, max-age=300, must-revalidate`. A comment
  in `src/lib.rs` marks the place to restore `immutable` once
  persistence lands in v0.2.0. ETags are unchanged.
- **FIX 2 — JSON integers outside `i64::MIN..=u64::MAX` are rejected.**
  The JSON-path handler recursively walks `serde_json::Value` and
  returns `400 { "error": "integer out of DAG-CBOR range", "detail": … }`
  for any integer literal that would otherwise silently become an f64
  and diverge from `cbor2`'s canonical bignum encoding. The
  `arbitrary_precision` feature was *not* enabled — bignum support is
  v0.2.0 scope.
- **FIX 3 — `GET /v1/blocks/{cid}` distinguishes 400 from 404.** A
  malformed CID returns `400 { "error": "malformed CID", … }`; a
  well-formed CID with no stored block returns
  `404 { "error": "block not stored", … }`. v0.1.0 returned 400 in
  both cases.
- **FIX 4 — `application/vnd.ipld.dag-cbor` is handled natively.**
  When the caller sets this Content-Type, the server decodes the body
  to `Ipld`, re-encodes to canonical DAG-CBOR, byte-compares to the
  input, and publishes with codec `0x71` (dag-cbor). Non-canonical
  inputs are rejected with `400 { "error": "non-canonical DAG-CBOR", … }`.
  v0.1.0 silently routed this MIME type to the raw-bytes path (codec
  `0x55`) so pre-encoded dag-cbor produced a `bafkrei…` CID instead
  of a `bafyrei…` CID.
- **FIX 5 — OpenAPI completeness.** Added `CertificateBlock` schema
  listing all eight cert-block fields with CBOR-level types; documented
  body-size limits (10 MB for JSON, 100 MB for octet-stream and
  dag-cbor); wired `axum::extract::DefaultBodyLimit` explicitly;
  enumerated every 400 tag, plus 404 on GET and 413 on POST.
- **FIX 6 — Narrowed the "Babel Fish" framing.** Both `README.md` and
  the OpenAPI `info.description` now distinguish **content identity +
  admission proof** (what this service delivers) from **semantic
  translation** (what it doesn't — URDNA2015 / JCS / dag-json ↔
  dag-cbor normalization). A Scope section at the top of the README
  enumerates what is and isn't delivered, matching the scoping
  discipline the architect review established for `sem-ipld` itself.

### Tests

- All 4 integration tests from v0.1.0 (`tests/absolute_urls.rs`) still
  pass.
- No new test files were added to this patch; the curl acceptance
  sequence from the audit prompt was executed end-to-end.

### Deliberately not done in v0.1.1

- `DashMap` → durable store swap (R2/S3). Tracked for v0.2.0.
- `serde_json` `arbitrary_precision` + bignum encoding. v0.2.0.
- URDNA2015 / JCS / any semantic normalization layer. v0.3.0+.
- Rate limiting, auth, CORS policy changes. Deferred.
- New endpoints. The surface is two verbs. It stays two verbs.

## 0.1.0 — Initial release

- `POST /v1/certify` — run UOR kernel admission and publish the linked
  IPLD block pair.
- `GET /v1/blocks/{cid}` — IPIP-402 trustless gateway.
- `GET /v1/health` — uptime probe.
- `GET /v1/openapi.yaml` — hand-written OpenAPI 3.1 spec.
- `BlockStore` enum for swappable storage (InMemory variant only).
- Absolute URLs derived from `PUBLIC_BASE_URL` / `X-Forwarded-*` / `Host`.
