# sem-ipld

[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](openapi.yaml)
[![Swagger UI](https://img.shields.io/badge/Swagger_UI-live-85EA2D?logo=swagger&logoColor=black)](https://petstore.swagger.io/?url=https://api.uor.foundation/v1/openapi.yaml)

**Content-addressed, W3C-verifiable identity for anything you can serialize.**

Three Rust crates:

| Crate | Purpose |
|---|---|
| [`sem-ipld`](crates/sem-ipld/) | Library. Projects UOR-admitted values into IPLD + JSON-LD + SRI-2. |
| [`uor-vc-crypto`](crates/uor-vc-crypto/) | Two W3C Data Integrity 1.0 cryptosuites — unsigned + Ed25519-signed. |
| [`sem-ipld-service`](crates/sem-ipld-service/) | HTTP service: `POST /v1/certify` + IPIP-402 block gateway. |

## The one-paragraph pitch

You hand the service any payload — a JSON object, a PDF, a model
artifact — and get back a permanent content-addressed identifier
(CIDv1), a UOR admission certificate, and a W3C Verifiable Credential
(2.0). The credential is consumable by any W3C verifier with no
UOR-specific code via the registered cryptosuite `uor-dag-cbor-2025`.
Anything that can `curl` integrates. Anything that reads IPFS reads
our blocks.

## API

The full contract lives in [`openapi.yaml`](openapi.yaml) at the repo root (OpenAPI 3.1.0).
The running service also serves it at `GET /v1/openapi.yaml`.

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/certify` | `POST` | Admit any payload → returns `data_cid`, `certificate_cid`, SRI integrity, W3C VC URLs |
| `/v1/blocks/{cid}` | `GET` | IPIP-402 trustless gateway — raw block, JSON-LD, or VC 2.0 projection |
| `/v1/health` | `GET` | Liveness probe + store descriptor + signing state |
| `/v1/openapi.yaml` | `GET` | This spec |

Browse interactively: **[Swagger UI →](https://petstore.swagger.io/?url=https://api.uor.foundation/v1/openapi.yaml)**

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

Full spec: [`crates/sem-ipld-service/docs/specs/uor-dag-cbor-2025.md`](crates/sem-ipld-service/docs/specs/uor-dag-cbor-2025.md).

## Deploy

One click, via Railway. New project → deploy from this repo →
**Settings → Volumes** → mount `/data` → **Generate Domain**. Done.

Full walk-through with smoke tests, signed-mode setup, and day-2
operations: [deploy/DEPLOY.md](deploy/DEPLOY.md).

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
