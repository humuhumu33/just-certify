# sem-ipld

> **UOR is the Digital Babel Fish.** A tiny universal translator that you quietly drop into any existing system — Web2, Web3, Semantic Web, AI — and suddenly every object it produces speaks a common underlying language of **permanent identity + verifiable semantic proof**, while the host system keeps speaking its native format (JSON, DAG-CBOR, RDF, model weights) with zero modifications.

sem-ipld is the surgical adapter between the UOR Foundation micro-kernel and that ambient web. UOR changes nothing in any existing system. sem-ipld is the thin convenience layer on top of a one-file IPLD adapter — every concern the upstream Rust ecosystem already solves well is delegated to that upstream crate, not reimplemented here.

## What the Babel Fish does in one paragraph

Every ecosystem's adapter ultimately answers one question: *"what are the canonical bytes of my native object?"* Once those bytes exist, `uor_foundation::Hasher::fold_bytes` → `ContentFingerprint` → `GroundingCertificate` is identical across Web2, Web3, and AI. sem-ipld picks **DAG-CBOR** as the one canonicalization, so the fingerprint a Web2 service emits as an `X-UOR-Fingerprint` header equals the fingerprint an IPFS gateway computes over the same payload, equals the fingerprint an AI registry assigns to the same metadata. Identity is shared across ecosystems because canonicalization is shared. Verified in code by `tests/babel_fish.rs`.

## Insert the Babel Fish into your stack

| Your system's native language | One-file adapter | Reference |
|---|---|---|
| Web2 / HTTP + JSON | Canonicalize via DAG-CBOR → fingerprint → `X-UOR-*` response headers | [`examples/adapter_web2_http.rs`](examples/adapter_web2_http.rs) (~40 LOC) |
| Web3 / IPLD + IPFS | `publish_semantic(...)` or `publish_parts(...)` | This crate |
| Semantic Web / RDF / Solid | `project_grounded` + `load_as_jsonld` (full duplex) | This crate's `jsonld` module |
| AI / models / datasets / agents | Wrap weights + metadata in a `SemanticBlock` | [`examples/adapter_ai_model.rs`](examples/adapter_ai_model.rs) (~50 LOC) |
| Unstructured blobs (PDF, image, audio, code) | One call: `publish_raw(&ctx, bytes, …)` | [`examples/adapter_unstructured.rs`](examples/adapter_unstructured.rs) (~40 LOC) |
| Any future protocol | Implement `uor_foundation::Hasher` once | ~20 LOC |

The inserted system keeps working exactly as before. What changes: every object it produces now carries a content-derived identity and a cryptographic admission proof that any other system — regardless of native format — can verify without converters, gateways, or trust intermediaries.

### Structured and unstructured, one path

- **Structured** (`serde::Serialize`): CSV rows, JSON trees, Protobuf messages, Parquet schemas, typed model metadata — all canonicalize through `publish_parts` (→ DAG-CBOR → CIDv1).
- **Unstructured** (opaque bytes): PDFs, images, audio, video, tar archives, raw model weights — all canonicalize through `publish_raw` (→ CBOR byte string → same CIDv1 shape).

Both paths terminate in the same `SemanticBlock`: one `data_cid`, one `certificate_cid`, one SRI attribute. The Anima-style hard-coded extension dispatch is replaced by one path per kind (structured / unstructured) and nothing else.

```rust
use sem_ipld::prelude::*;

let context = SemanticContext::with_bytes(
    SemanticContext::CANONICAL_IRI, UOR_CONTEXT_BYTES,
)?;

// `grounded` comes out of uor_foundation::pipeline::run_*.
let block = publish_semantic(&grounded, &context, payload_json)?;

//   block.data_cid          ← CID v1 of the structural content
//   block.certificate_cid   ← CID v1 of the UOR proof block (links back)
//   block.integrity_attr    ← `sha256-…` for <link integrity="…">
//   block.data_bytes        ← deterministic DAG-CBOR for IPFS put
//   block.certificate_bytes ← deterministic DAG-CBOR

let input: SemanticInput = load_as_jsonld(&jsonld_value)?;
// input.context_iri, input.context_cid, input.payload
// → hand to pipeline::run_* to obtain a fresh Grounded<T>.
```

## v0.2.0 — the micro-kernel pass

| Was (v0.1.0) | Now (v0.2.0) |
|---|---|
| 1,979 LOC src/ | **733 LOC src/** (−63%) |
| Hand-rolled CID, DAG-CBOR, varint, base32, base64 | `cid`, `serde_ipld_dagcbor`, `base64` (upstream) |
| Three hasher types (SriHasher256/384/512) | One: `SriHasher256` |
| Three error enums | One: `sem_ipld::Error` |
| PROV projection inside the crate | Dropped — belongs in its own adapter |
| Module tree with 5 sub-directories | Top-level single files: `hasher`, `ipld`, `integrity`, `jsonld`, `context`, `publish` |

## Feature matrix

| Feature   | Default | Surface it turns on |
|-----------|---------|---------------------|
| (none)    | on      | `#![no_std]`: `SriHasher256`, `sha256()`, multicodec/multihash constants. |
| `alloc`   | off     | `cid`, `serde_ipld_dagcbor`, `base64` — the IPLD + integrity adapters. |
| `std`     | off     | std-only conveniences. Implies `alloc`. |
| `serde`   | off     | JSON-LD projection, `load_as_jsonld`, `publish_semantic`. Implies `alloc`. |
| `publish` | off     | `alloc + serde` — what most application code wants. |

## Module surface (everything in src/)

```
src/
├── lib.rs              # crate root, Error, prelude        (187 LOC)
├── hasher/mod.rs       # SriHasher256 + multicodec consts  (86 LOC)
├── ipld.rs             # cid_from_sha256 + dag_cbor_cid + encode (53 LOC)
├── integrity.rs        # sha256_integrity_attribute        (30 LOC)
├── context.rs          # SemanticContext — pins ontology CID (52 LOC)
├── jsonld.rs           # project_grounded + load_as_jsonld (161 LOC)
└── publish.rs          # publish_semantic + publish_parts  (159 LOC)
```

## Is sem-ipld actually rooted in UOR? (conformance evidence)

`tests/kernel_roundtrip.rs` builds a real `CompileUnit`, validates it,
runs `pipeline::run::<ConstrainedTypeInput, _, SriHasher256>()`, and
verifies that every field of the emitted cert block byte-matches the
kernel-produced `Grounded<T>`'s own accessors — `witt_bits`,
`witt_level_bits`, `unit_address`, `content_fingerprint`, plus the
data and context CID links. If the foundation changes the shape of
`Grounded<T>` or the kernel's outputs diverge from the cert-block
wire format, this test fires.

This is the load-bearing evidence that sem-ipld is *rooted in* UOR
and not just consuming UOR-shaped structs. Every other test in the
suite can, in principle, be satisfied by a mocked `Grounded<T>`.
`kernel_roundtrip.rs` cannot — it fails to compile or run without
threading the actual `uor_foundation::pipeline`.

The **only fully kernel-rooted publish path is `publish_semantic(&grounded, …)`**.
`publish_parts`, `publish_raw`, and the unified `publish()` entry
point all accept raw UOR primitives (`witt_bits`, `unit_address`,
`fingerprint`) and can therefore be used *without* the kernel —
useful for tests and for callers that have obtained the primitives
from a non-Rust kernel build, but by construction *not* a conformance
guarantee. Application code that claims UOR-rooted publication
should use `publish_semantic`.

## Anchors into `uor-foundation` (v0.3.0)

Every citation below is load-bearing.

| Surface in sem-ipld | Foundation anchor |
|---|---|
| `SriHasher256` implements | `uor_foundation::Hasher` — `enforcement.rs:5966` |
| `SriHasher256::OUTPUT_BYTES` bound | `FINGERPRINT_MAX_BYTES = 32` — `enforcement.rs:5888` |
| `publish_semantic` reads | `Grounded<T>::{witt_level_bits, unit_address, content_fingerprint, certificate}` — `enforcement.rs:7329+` |

## The structural-vs-proof split (v0.1 decision preserved)

The data block carries **only structural content**:

```
{ contextCid: <cid>, contextIri: <text>, payload: <opaque serde> }
```

The certificate block carries **only UOR proof state**, with an IPLD CID link back to the data block:

```
{ data: <cid₁>, fingerprint: <bytes>, unitAddress: <uint>,
  wittBits: <uint>, wittLevelBits: <uint> }
```

Consequence: two `Grounded<T>` values with the same structural payload but different constraints produce **identical `data_cid`s** and **distinct `certificate_cid`s**. Verified by `round_trip::data_cid_is_independent_of_uor_state`.

## What the overlay deliberately does *not* do

- **Construct `Grounded<T>` values.** Sealed by design. Admission is the kernel's job.
- **Emit PROV / VC / SHACL.** Additional formats are separate ≤50-LOC adapters. `GroundingCertificate` is already a cryptographic witness.
- **Implement wide SRI digests.** SHA-384 / SHA-512 are a 20-LOC adapter on top of `sha256_integrity_attribute` if a caller needs them.

## Run the canonical examples

```sh
cargo run --example round_trip          --features publish   # IPLD + JSON-LD round-trip
cargo run --example adapter_web2_http   --features publish   # emit X-UOR-* HTTP headers
cargo run --example adapter_ai_model    --features publish   # fingerprint a model artifact
```

## Deployment scope (read this before shipping)

sem-ipld v0.2.2 is architecturally honest for **single-writer or trusted-cluster** deployments. For **federated / low-trust / multi-writer** deployments it is missing one layer that a companion crate is expected to provide. Each of the limits below was surfaced by an independent architectural review.

| Concern | State in v0.2.2 | What you need to add for federated / production deployment |
|---|---|---|
| Cert block authenticity | Unsigned; fields are pointers, not cryptographic claims. Re-admit via the kernel to trust. | A companion **UCAN 0.10+** layer (`sem-ipld-ucan`, planned for v0.3.0): the publisher's DID or libp2p peer-identity key signs `{data_cid, context_cid, wittBits, wittLevelBits, unitAddress, fingerprint}`. Signature check (µs) replaces re-admission (s). |
| VC 2.0 interop | **Out of scope.** Cert block is DAG-CBOR; VC 2.0 wants JSON-LD + JWS/DataIntegrityProof. | A companion **`sem-ipld-vc`** crate (~200 LOC) that projects the cert block into `{@context, type: VerifiableCredential, credentialSubject, issuer, proof}` with a pluggable Data-Integrity cryptosuite. |
| Data → cert index | **Your responsibility.** IPFS DHT is one-directional; given `data_cid` you cannot enumerate cert CIDs. | Postgres / IPNI / signed VC registry. Build before production or multi-writer reconciliation fails. |
| Gateway response framing (**SRI footgun**) | `integrity_attr` verifies against raw bytes only. Public IPFS gateways default to decoded JSON. | Always request `?format=raw` or `Accept: application/vnd.ipld.raw` (IPIP-402). See `src/integrity.rs` docs. |
| Context CID pinning | Cert block pins the ontology CID; you must pin it operationally on both publishers and consumers. | Pin `SemanticContext::cid` as a permanent root on every node. Kubo GC will otherwise discard it. |
| Codec minor-version drift | `serde_ipld_dagcbor` determinism is verified by our tests today. | Pin the codec minor version in downstream `Cargo.lock`; our `tests/golden_cids.rs` fires on any wire-byte change. |

## Test coverage

32 integration tests, all passing:

- `sri_hashers.rs` (4) — NIST FIPS 180-4 vectors; `uor_foundation::Hasher` impl conformance.
- `cid_and_integrity.rs` (4) — CIDv1(dag-cbor, sha2-256) prefix + codec + multihash; SRI attribute format.
- `round_trip.rs` (9) — data CID independent of UOR state; cert block embeds `Ipld::Link` back to data_cid; `load_as_jsonld` / `_strict` variants; `publish_raw` opaque-bytes coverage.
- `babel_fish.rs` (5) — **three adapters independently converge on one `data_cid`** (honest cross-adapter test); byte equality Web2 ≡ Web3 `data_bytes`; opaque-blob CID identity across transports; cert ≠ data CID; integrity attr scope (CBOR vs. raw JSON).
- `determinism_audit.rs` (6) — `serde_ipld_dagcbor` sorts `serde_json::Value` keys canonically (flat + nested); NaN/Infinity rejected at `serde_json::Number`; idempotence; negative-zero diagnostic; integrity scope divergence.
- `golden_cids.rs` (4) — **frozen canonical bytes**, frozen CID strings for structured and raw payloads, cert block field count locked at 8 (`foundationVersion` included).

## License

Apache-2.0
