# sem-ipld-service

**Two HTTP verbs. Every system gets a shared way to name and re-verify objects.**

## Scope (read this first)

**UOR is the Babel Fish for content identity and admission proof.** It gives any system a shared way to *name* and *re-verify* objects without changing wire formats. **Semantic translation** — canonicalizing different serializations of the same meaning to the same CID — is an adjacent layer (URDNA2015 for RDF, JCS for JSON) that composes on top. It is **not** a property this service delivers alone.

Two different JSON-LD serializations of the same RDF graph will produce two different CIDs here, by design.

| This service delivers | This service does NOT deliver |
|---|---|
| Content-addressed CIDv1 identifiers (`bafyrei…` / `bafkrei…`) | VC 2.0 signing / proof suites |
| UOR admission certificates (kernel-minted `Grounded<T>` metadata) | DID resolution |
| IPIP-402 trustless gateway for raw block fetch | Semantic canonicalization (URDNA2015 / JCS / dag-json ↔ dag-cbor normalization) |
| Deterministic DAG-CBOR encoding for structured JSON / native dag-cbor | Durable cross-restart storage (v0.2.0 scope) |
| Raw-bytes path for PDFs, images, model weights, etc. | Rate limiting, auth, CORS policy (deferred) |

## Example

```bash
# POST any payload → get back a permanent id, a data CID, and a cert CID.
$ curl -X POST http://localhost:8787/v1/certify \
       -H 'Content-Type: application/json' \
       -d '{"agent":"ada","trust":0.98}'
{
  "id":              "bafyreidtr26vo7c46ehidi7eqadhku22gn32p6k3r36pnh6dligq5dnjke",
  "data_cid":        "bafyreidlinmf2dfsv4vlwz6qd3264vt7lou2gcfisa3i62tpgzigqxx5iu",
  "certificate_cid": "bafyreidtr26vo7c46ehidi7eqadhku22gn32p6k3r36pnh6dligq5dnjke",
  "integrity":       "sha256-a0NYXQyyryq7Z9Ae9e5Wf1upowiokDaPam82UGhe/UU=",
  "foundation_version": "0.3.0",
  "context": { "iri": "https://uor.foundation/", "cid": "bafyreig2u5g3vjapucxortr…" },
  "urls":    { "data": "http://localhost:8787/v1/blocks/bafyrei…",
               "cert": "http://localhost:8787/v1/blocks/bafyrei…" }
}

# GET the raw IPLD block by CID — IPIP-402 trustless gateway.
$ curl -i http://localhost:8787/v1/blocks/bafyrei…
HTTP/1.1 200 OK
content-type: application/vnd.ipld.raw
cache-control: public, max-age=300, must-revalidate
etag: "bafyrei…"

<raw bytes>
```

## What it does under the hood

Every `POST /v1/certify` runs the full UOR kernel admission:

1. `uor_foundation::enforcement::CompileUnitBuilder::new().…validate()`
2. `uor_foundation::pipeline::run::<ConstrainedTypeInput, _, sem_ipld::SriHasher256>(validated)` — produces a real `Grounded<T>`.
3. The caller's payload is stored in the data block (codec by Content-Type — see below); the kernel-minted UOR metadata lands in the cert block.
4. Both blocks land in an in-memory `DashMap` keyed by CID. Swap for Redis / R2 / Fastly KV in production.
5. Response returns the CIDs, the SRI integrity attribute, and two absolute gateway URLs.

`GET /v1/blocks/{cid}` is the IPIP-402 trustless-gateway endpoint — always returns `application/vnd.ipld.raw` with the exact bytes the CID addresses.

## Endpoints

| Method | Path                  | Purpose |
|--------|-----------------------|---------|
| POST   | `/v1/certify`         | Run kernel admission + publish block pair. |
| GET    | `/v1/blocks/{cid}`    | Fetch a raw IPLD block. IPIP-402 conformant. |
| GET    | `/v1/health`          | Uptime probe. Returns `ok`. |
| GET    | `/v1/openapi.yaml`    | The OpenAPI 3.1 spec. |

## Content-Type negotiation on `POST /v1/certify`

| Request `Content-Type`                  | Path                    | Data-block codec | Max body |
|-----------------------------------------|-------------------------|------------------|----------|
| `application/json`                      | Structured → DAG-CBOR   | `dag-cbor` (0x71) | 10 MB |
| `application/vnd.ipld.dag-cbor`         | Native dag-cbor         | `dag-cbor` (0x71) | 100 MB |
| `application/octet-stream` (or absent)  | Opaque bytes            | `raw` (0x55)      | 100 MB |
| anything else                           | Opaque bytes (+ warn log) | `raw` (0x55)    | 100 MB |

**JSON integer range.** DAG-CBOR integer major types 0/1 max at `u64::MAX`. v0.1.x rejects any JSON integer outside `i64::MIN..=u64::MAX` with HTTP 400 `integer out of DAG-CBOR range`; arbitrary-precision bignums (CBOR tag 2) are not supported. Encode large values as byte strings.

**Native dag-cbor canonicality.** Requests with `Content-Type: application/vnd.ipld.dag-cbor` are checked for canonical form (decode → re-encode → byte-compare). Non-canonical input is rejected with HTTP 400 `non-canonical DAG-CBOR` — the server refuses to silently re-canonicalize because doing so would change the CID.

## Signing and Trust (v0.4.0)

The service runs in one of two modes, selected by a single env var:

| Mode        | Env var                      | Cryptosuite emitted                  | Trust model |
|-------------|------------------------------|--------------------------------------|-------------|
| **Unsigned** (default) | — (unset)        | `uor-dag-cbor-2025`                  | Tamper-evidence. Anyone with the canonical bytes can compute the same proof. Suitable for single-writer / trusted-cluster deployments. |
| **Signed**  | `SEM_IPLD_ISSUER_KEY_B64=<base64 seed>` | `uor-dag-cbor-ed25519-2025` | Tamper-evidence + authenticity. Only the key-holder can produce the proof. Suitable for federated / multi-party / EUDI-wallet scenarios. |

`/v1/health` publishes the current mode — `signing.enabled`, plus
(when enabled) `algorithm`, `verification_method`, and the public
key in W3C Multikey format. Downstream verifiers resolve the public
key via this endpoint (or via the service's `did:web:uor.foundation`
DID document, once hosted).

Key generation (operator-side, one-time):

```bash
cargo run --release -p uor-vc-crypto --bin gen-issuer-key
# private_key_b64:      <paste into SEM_IPLD_ISSUER_KEY_B64>
# public_key_multibase: <paste into docs/did/did.json>
# verification_method:  did:web:uor.foundation#key-1
# self_check:           ok
```

Full operator checklist in `docs/did/README.md`. The cryptosuite
spec document is at `docs/specs/uor-dag-cbor-2025.md`.

## W3C Semantic Web integration (v0.3.0)

Every cert block is simultaneously available in three equivalent forms:

| Consumer | Endpoint | Content-Type |
|---|---|---|
| IPLD / IPFS clients (Kubo, Helia) | `GET /v1/blocks/{cid}` | `application/vnd.ipld.raw` |
| JSON-LD processors (Sophia, jsonld.js) | `GET /v1/blocks/{cid}?as=jsonld`<br/>or `Accept: application/ld+json` | `application/ld+json` |
| VC 2.0 verifiers (vc-js, didkit) | `GET /v1/blocks/{cid}?as=vc`<br/>or `Accept: application/vc+ld+json` | `application/vc+ld+json` |

The three projections share a single canonical form: the DAG-CBOR
bytes the CID addresses. JSON-LD is a view; the VC is a signed VC
built from that view. Tampering with any byte in the VC invalidates
the proof — the signature is the CID of the VC's canonical form
minus `proofValue`.

### The cryptosuite

`uor-dag-cbor-2025` is implemented in the sibling crate `uor-vc-crypto`.
The `proofValue` is a content-addressed CID — integrity without
requiring a specific key-holder. A signed variant
(`uor-dag-cbor-ed25519-2025`) is planned for federated deployments.

Formal W3C registration (via PR to `w3c/vc-extensions`) requires a
stable spec document at `https://uor.foundation/specs/uor-dag-cbor-2025/`.
That document is out of scope for v0.3.0 but is tracked as the next
non-code deliverable. Credentials emitted today are *de facto*
valid — they use the registered Data Integrity 1.0 `DataIntegrityProof`
type with a namespaced custom cryptosuite name.

### `did:web:uor.foundation` hosting

Every VC's `issuer` is `did:web:uor.foundation`. For external
verifiers to resolve the DID document, the file at
`docs/did/did.json` in this repo must be served at
`https://uor.foundation/.well-known/did.json` with
`Content-Type: application/did+ld+json`. See
`docs/did/README.md` for the hosting checklist.

Because `uor-dag-cbor-2025` is unsigned in v0.3.0, verifiers can
confirm *integrity* (the bytes canonicalize to this CID) without
resolving the DID document at all. The DID hosting becomes
load-bearing the moment the signed variant ships.

## v0.2.0 cache policy (post-durability)

- **`GET /v1/blocks/{cid}`** returns `Cache-Control: public, max-age=31536000, immutable`.
  Kubo pins every block we store (`pin=true` on `block/put`), so the
  CID → bytes mapping survives restarts and the `immutable` directive
  is accurate. CDNs can cache these responses forever.
- **`POST /v1/certify`** returns `Cache-Control: public, max-age=300, must-revalidate`.
  Response bodies embed `urls.data` / `urls.cert` absolute URLs that
  can legitimately change across deployments — so the response is
  cacheable but not immutable. 5 minutes is enough to collapse
  thundering-herd patterns without pinning stale URLs at the edge.

## Running against Kubo

The default (and recommended) store in v0.2.0 is a **local Kubo
daemon running as a sidecar on the same machine or pod**. Three
steps to stand it up locally:

1. Install Kubo. Linux/macOS: download from <https://dist.ipfs.tech/>
   and put `ipfs` on your PATH. Windows: `choco install kubo` or
   download the binary.
2. Initialize once, with the `server` profile so Kubo doesn't
   flood the local network with mDNS / DHT announce traffic:

   ```bash
   ipfs init --profile=server
   ipfs daemon        # leave running in a separate terminal
   ```

3. Start `sem-ipld-service`. The default `SEM_IPLD_STORE=kubo`
   points at `http://127.0.0.1:5001`:

   ```bash
   cargo run --release --bin sem-ipld-service
   ```

The service **refuses to start** if the Kubo daemon isn't reachable
— this is intentional. A running service that silently returns 503
on every request is worse than a service that won't come up; the
orchestrator (systemd / Kubernetes / docker-compose) is the one that
should decide when to retry.

For tests only: `SEM_IPLD_STORE=memory cargo run --bin sem-ipld-service`
uses an in-memory `DashMap`. Not durable; `Cache-Control: immutable`
on block reads is still emitted because the cache contract is per
*block-CID resolution*, but in practice you'll restart the service
and see 404s — this mode exists for local development where that's
expected.

## Configuration

All config via env vars; defaults shown first.

| Variable                    | Default                   | Purpose |
|-----------------------------|---------------------------|---------|
| `SEM_IPLD_STORE`            | `kubo`                    | `kubo` or `memory`. Memory is for tests only. |
| `SEM_IPLD_IPFS_API_URL`     | `http://127.0.0.1:5001`   | Kubo RPC endpoint. |
| `SEM_IPLD_IPFS_TIMEOUT_MS`  | `5000`                    | Per-call timeout against Kubo. |
| `SEM_IPLD_LRU_CAPACITY`     | `10000`                   | Entries in the in-process LRU cache in front of the Kubo reads. ≈40 MB at 4 KB avg block size. |
| `SEM_IPLD_BIND`             | `127.0.0.1:8787`          | Bind address. |
| `PUBLIC_BASE_URL`           | (unset)                   | Absolute base URL for `urls.data` / `urls.cert` in responses. Set this behind a CDN. Overrides `X-Forwarded-*` header detection. |

Example production invocation behind a CDN:

```bash
SEM_IPLD_STORE=kubo \
SEM_IPLD_IPFS_API_URL=http://ipfs-sidecar.local:5001 \
SEM_IPLD_LRU_CAPACITY=50000 \
PUBLIC_BASE_URL=https://api.uor.foundation \
SEM_IPLD_BIND=0.0.0.0:8080 \
  sem-ipld-service
```

## URL derivation (important for CDN deployments)

`urls.data` and `urls.cert` in every certify response are **absolute**, derived in this precedence order:

1. **`PUBLIC_BASE_URL` env var** — operator-controlled, defeats any hostile `X-Forwarded-Host` injection.
2. **`X-Forwarded-Proto` + `X-Forwarded-Host`** — standard CDN / proxy convention.
3. **`Host` header** + `http://` fallback scheme — when no proxy headers are set.

All three paths are covered by regression tests in `tests/absolute_urls.rs`.

## Block store — variant-based, swap for durability

`enum BlockStore` in `src/store.rs`. v0.1.x ships `InMemory` only. Adding an `S3` / `R2` variant is one new arm in each method — the compiler forces exhaustive coverage.

## Latency targets

| Operation                    | p50    | p99    |
|------------------------------|--------|--------|
| `POST /certify` (cache hit)  | < 5 ms | < 20 ms |
| `POST /certify` (cold)       | < 25 ms | < 80 ms |
| `GET /blocks/{cid}`          | < 2 ms | < 15 ms |

## License

Apache-2.0
