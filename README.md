# sem-ipld

**Content-addressed, W3C-verifiable identity for anything you can serialize.**

Three Rust crates:

| Crate | Purpose |
|---|---|
| [`sem-ipld`](sem-ipld/) | Library. Projects UOR-admitted values into IPLD + JSON-LD + SRI-2. |
| [`uor-vc-crypto`](uor-vc-crypto/) | Two W3C Data Integrity 1.0 cryptosuites — unsigned + Ed25519-signed. |
| [`sem-ipld-service`](sem-ipld-service/) | HTTP service: `POST /v1/certify` + IPIP-402 block gateway. |

## The one-paragraph pitch

You hand the service any payload — a JSON object, a PDF, a model
artifact — and get back a permanent content-addressed identifier
(CIDv1), a UOR admission certificate, and a W3C Verifiable Credential
(2.0). The credential is consumable by any W3C verifier with no
UOR-specific code via the registered cryptosuite `uor-dag-cbor-2025`.
Anything that can `curl` integrates. Anything that reads IPFS reads
our blocks.

## Quick start

```bash
# Dependencies: Rust 1.81+, Kubo (IPFS).
ipfs init --profile=server && ipfs daemon &

# Build and run.
cargo run --release --bin sem-ipld-service

# POST a payload.
curl -X POST http://127.0.0.1:8787/v1/certify \
     -H 'Content-Type: application/json' \
     -d '{"hello":"world"}'
```

Response carries `data_cid`, `certificate_cid`, `integrity`,
`digestMultibase`, and four URLs (`data`, `cert`, `jsonld`, `vc`).

## `uor-foundation` dependency

All three crates depend on
[`uor-foundation`](https://github.com/uor-foundation/UOR-Framework)
via a path dependency. Clone it next to this repo:

```
your-workspace/
├── <this repo>/
└── UOR-Framework/
    └── foundation/
```

## The two cryptosuites

| Name | `proofValue` | Use when |
|---|---|---|
| `uor-dag-cbor-2025` | CID of canonical form | Tamper-evidence for single-writer / trusted-cluster. |
| `uor-dag-cbor-ed25519-2025` | Ed25519 signature over CID multihash | Tamper-evidence + authenticity for federated / multi-party. |

Enable the signed variant by setting `SEM_IPLD_ISSUER_KEY_B64` on
the service. Generate a key with
`cargo run --release -p uor-vc-crypto --bin gen-issuer-key`.

Full spec: [`sem-ipld-service/docs/specs/uor-dag-cbor-2025.md`](sem-ipld-service/docs/specs/uor-dag-cbor-2025.md).

## Releases

Four release cycles, each with a CHANGELOG in the corresponding
crate:

- **v0.1.x** — HTTP surface + correctness fixes.
- **v0.2.x** — durability (Kubo sidecar).
- **v0.3.x** — W3C alignment (JSON-LD + VC 2.0 projections,
  `uor-dag-cbor-2025`).
- **v0.4.x** — signed cryptosuite, DID publication, spec document,
  OpenAPI completeness sweep.

## License

Apache-2.0. See [LICENSE](LICENSE).
