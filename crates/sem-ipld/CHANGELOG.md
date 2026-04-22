# Changelog

All notable changes to `sem-ipld` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-04-22

Adversarial review cycle. Three correctness findings, three architectural
findings, and the Babel Fish claim (C1) rewritten from a narrative into a
tested property. LOC grew from 767 → ~790; test count grew from 18 → 28.
The net of the review is a crate that claims less and proves more.

### Fixed

- **Silent `u128 → u64` truncation of `unit_address`.** `publish_semantic`
  previously cast `ContentAddress::as_u128()` to `u64` before serialization
  into the cert block. Any kernel address in the upper half of the 128-bit
  space was silently corrupted with no error. `publish_parts` and
  `publish_raw` now take `unit_address: u128` and encode it as a 16-byte
  big-endian byte string (`unitAddress` field in the cert block).
  ([`src/publish.rs`](src/publish.rs))

- **Tautological Babel Fish tests.** The previous
  `tests/babel_fish.rs` asserted `f(x) == f(x)` for shared code paths
  and dressed the tautology in "Web2 / Web3 / AI" framing. The file is
  rewritten: `three_adapters_converge_on_one_data_cid` now exercises
  three independent computation paths (simulated Web2, simulated AI,
  and the real `publish_parts` path) and checks all three agree on a
  single `data_cid`. `web2_bytes_equal_web3_data_bytes` asserts byte
  identity across transports. `opaque_bytes_cid_is_shared_across_transports`
  does the same for the `raw`-codec path. ([`tests/babel_fish.rs`](tests/babel_fish.rs))

### Changed

- **Data block is now payload-only; context moved to the cert block.**
  In 0.2.0 the data block was `{ contextCid, contextIri, payload }`,
  which meant `data_cid` was a function of `(payload, context)` rather
  than `payload` alone — the Babel Fish claim held only conditionally.
  In 0.2.1 the schema is:

  ```text
  data block:  <canonical payload bytes>              (codec: dag-cbor OR raw)
  cert block:  { context, contextIri, data, fingerprint,
                 unitAddress, wittBits, wittLevelBits } (codec: dag-cbor)
  ```

  Now `data_cid = CIDv1(dag-cbor, sha2-256, serde_ipld_dagcbor::to_vec(payload))`
  for structured payloads and `data_cid = CIDv1(raw, sha2-256, bytes)`
  for opaque ones. The same payload published under two different
  ontology contexts produces the same `data_cid` and different
  `certificate_cid`s — semantic versioning over byte immutability, the
  property the architecture always claimed.

- **`publish_raw` emits `raw` codec (0x55), not `dag-cbor` (0x71).**
  Opaque bytes are now published as an IPFS `raw` block whose CID matches
  what `ipfs add` would produce for the same file. No serialization
  wrapper. The previous `dag-cbor` wrapping made `publish_raw`'s CID
  incompatible with direct IPFS ingestion of the same bytes.

### Added

- **`tests/determinism_audit.rs`** — the reviewer's requested audit.
  Six tests:
  - `dag_cbor_value_map_is_key_sorted_regardless_of_insertion_order`
    — confirms `serde_ipld_dagcbor` sorts `serde_json::Value::Object`
    keys canonically at the top level. The feared correctness hole is
    **absent**.
  - `dag_cbor_value_nested_map_is_key_sorted` — same property for
    nested maps.
  - `dag_cbor_rejects_or_handles_nan` — documents that
    `serde_json::Number` itself rejects NaN and Infinity, so non-finite
    floats never reach the encoder through the `Value` path.
  - `dag_cbor_negative_zero_behavior` — diagnostic test reporting
    whether `-0.0` and `+0.0` produce identical CBOR bytes.
  - `dag_cbor_is_idempotent` — explicit idempotence check.
  - `integrity_attr_scope_is_dag_cbor_envelope_not_raw_payload` —
    locks in that the SRI attribute's scope is the DAG-CBOR envelope,
    not the original payload. A future change that silently changes
    the scope will fail this test.

- **`load_as_jsonld_strict`** — explicit strict-mode loader that rejects
  pass-through / incomplete-envelope inputs rather than silently
  returning a `SemanticInput` with ambiguous payload content.

- **Security-scope documentation on `SemanticBlock`.** Two blocks of
  doc comments now make the following explicit and citable:
  1. The cert block is **not self-signed**. Its `wittBits`,
     `wittLevelBits`, `unitAddress`, and `fingerprint` fields are
     recoverable pointers for a consumer that intends to re-run
     `uor_foundation::pipeline::run_*`. They are not cryptographic
     claims. An adversary with write access to the cert bytes can
     fabricate arbitrary witt state pointing at any `data_cid`; the
     kernel's sealing guarantee applies only to a live `Grounded<T>`,
     not to its serialized projection.
  2. The `integrity_attr` is SHA-256 over `data_bytes` (the canonical
     DAG-CBOR / raw encoding). It does **not** cover the original serde
     value or any alternative serialization (e.g. raw JSON). Consumers
     serving a non-CBOR encoding must compute integrity separately.

### Known limitations (documented but not fixed)

- **No streaming publish path.** `publish_raw` currently takes
  `&[u8]`; large blobs (model weights, long-form video) must be
  resident in memory. A `publish_raw_streaming<R: Read>` entry point
  is a reasonable 0.3.0 addition.

- **No block store.** `sem-ipld` composes block bytes and CIDs;
  persistence is the caller's responsibility. A `uor-blockstore`
  companion crate is the right place for that abstraction, not here.

### Review provenance

The findings above came from a six-question adversarial review
conducted 2026-04-22. The reviewer's concrete patches (1), (2), and
(3) are the *Fixed* entries; the reviewer's §4 alternative design is
the *Changed — data block is now payload-only* entry; the reviewer's
§5 blockers are either addressed or documented under *Known
limitations*. No reviewer finding was dismissed without a concrete
response in code or docs.

## [0.2.0] — 2026-02-xx

Initial public cut of the "low proposal" overlay. Hand-rolled CID,
varint, base32, base64, and DAG-CBOR implementations (≈700 LOC)
deleted in favour of upstream (`cid`, `multihash`, `serde_ipld_dagcbor`,
`base64`). Crate is `#![no_std]` by default with optional `alloc`,
`std`, `serde`, and `publish` features. Single `SriHasher256` implements
`uor_foundation::Hasher`. Two publish paths: `publish_parts` for
structured payloads, `publish_raw` for opaque bytes. JSON-LD projection
and `load_as_jsonld` inverse provided behind the `serde` feature.

[0.2.1]: https://example.invalid/sem-ipld/releases/tag/v0.2.1
[0.2.0]: https://example.invalid/sem-ipld/releases/tag/v0.2.0
