# sem-ipld-service

[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI-3.1-6BA539?logo=openapiinitiative&logoColor=white)](openapi.yaml)
[![Swagger UI](https://img.shields.io/badge/Swagger_UI-live-85EA2D?logo=swagger&logoColor=black)](https://petstore.swagger.io/?url=https://api.uor.foundation/v1/openapi.yaml)
[![AI Tool](https://img.shields.io/badge/OpenAI_Tool-compatible-412991?logo=openai&logoColor=white)](/.well-known/ai-plugin.json)
[![JSON-LD 1.1](https://img.shields.io/badge/JSON--LD-1.1-005A9C)](https://www.w3.org/TR/json-ld11/)
[![W3C VC 2.0](https://img.shields.io/badge/W3C_VC-2.0-005A9C)](https://www.w3.org/TR/vc-data-model-2.0/)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Permissionless, permanent identity for any digital object. One POST. No registry. No trust required.**

---

## The problem

Every naming system today requires a naming authority:

- DNS requires registrars. DOIs require publishers. UUIDs are random — no meaning.
- SHA-256 hashes are format-dependent: re-encode the same JSON differently and you get a different hash.

They name things by *location* or *assignment* — not by *what they are*.

---

## What this service does

POST any object. Receive back a **`uor_address`** and an **`@id`**.

```
uor_address  →  the UOR kernel's canonical name for this object
@id          →  ipfs://<CID>  — the permanent, globally retrievable content address
```

The `uor_address` is not a hash of bytes. It is the output of a formal ontological kernel ([UOR-Framework](https://github.com/UOR-Foundation/UOR-Framework)) that evaluates the object's logical structure within a declared semantic context and produces a *canonical mathematical identity* — independent of encoding, location, or issuer.

The chain `uor_address → @id` means:

> *"This object was evaluated by the UOR kernel, received a provably canonical identity, and that identity was expressed as an IPLD content address anyone anywhere can retrieve and verify — without trusting you, the issuer, or any registry."*

No other system does all of that in one atomic operation.

---

## Quick start

```bash
# Requires: Rust 1.85+, Kubo (IPFS daemon).
ipfs init --profile=server && ipfs daemon &
cargo run --release --bin sem-ipld-service

# Certify anything.
curl -X POST http://127.0.0.1:8787/v1/certify \
     -H 'Content-Type: application/json' \
     -d '{"model":"gpt-5","eval_score":0.97,"dataset":"mmlu-v2"}'
```

Response (valid JSON-LD 1.1):

```json
{
  "@context": "https://uor.foundation/",
  "@type": "https://uor.foundation/state/GroundedContext",
  "uor_address": "z9Yrf1BFzxkMGXLmhzCxAivRPMBn3BwD",
  "@id": "ipfs://bafyreic72oorcja3h7e7suwg3qgdnfbdpyti3dy54zcebifn535yvq2lbq",
  "certificate": "ipfs://bafyreig3lqv5fblgr3vupfvzmxnbzq2xqrvqimhpjhbmxkynqpqcxpxhq4",
  "integrity": "sha256-U0fJjNb+W0AcFFYQmbmBdjP44x+Gg6z6GnYf5O4YWno=",
  "digestMultibase": "uEiArPBHXCiF2s4qwX4RCOcFujtR3WIwL53bBKjZnDCFaHg",
  "foundation_version": "0.3.0",
  "gateway": {
    "data":   "https://…/v1/blocks/bafyrei…",
    "cert":   "https://…/v1/blocks/bafyrei…",
    "jsonld": "https://…/v1/blocks/bafyrei…?as=jsonld",
    "vc":     "https://…/v1/blocks/bafyrei…?as=vc"
  }
}
```

`@id` is permanent. `certificate` is permanent. Both are retrievable from any public IPFS gateway — this service is not in the critical path for verification.

---

## API

| Endpoint | Method | What it does |
|---|---|---|
| `/v1/certify` | `POST` | Admit any payload → `uor_address` + `@id` + W3C VC certificate |
| `/v1/blocks/{cid}` | `GET` | IPIP-402 trustless gateway — raw, JSON-LD, or VC 2.0 projection |
| `/v1/health` | `GET` | Liveness probe + store descriptor + signing state |
| `/v1/openapi.yaml` | `GET` | Machine-readable API contract (OpenAPI 3.1.0) |
| `/.well-known/ai-plugin.json` | `GET` | OpenAI GPT Actions / ChatGPT Plugin manifest |
| `/v1/openai-tools` | `GET` | OpenAI function-calling definitions — paste into any agent |

Full contract: [`openapi.yaml`](openapi.yaml)  
Interactive browser: [Swagger UI →](https://petstore.swagger.io/?url=https://api.uor.foundation/v1/openapi.yaml)

---

## AI agent integration

This service is registered as an OpenAI-compatible tool. Any agent framework picks it up without integration code.

**ChatGPT / GPT Actions** — add the action URL and point to `/.well-known/ai-plugin.json`.

**LangChain:**
```python
from langchain.agents.agent_toolkits import OpenAPIToolkit
toolkit = OpenAPIToolkit.from_openapi_spec_url(
    "https://api.uor.foundation/v1/openapi.yaml"
)
```

**OpenAI SDK (any compatible model):**
```python
import requests, openai

tools = requests.get("https://api.uor.foundation/v1/openai-tools").json()
response = openai.chat.completions.create(
    model="gpt-4o",
    tools=tools,
    messages=[{"role": "user", "content":
        "Certify this model card: {'model': 'my-llm', 'version': '1.0'}"}]
)
```

**Claude / Anthropic tool use:**
```python
tools = requests.get("https://api.uor.foundation/v1/openai-tools").json()
# Pass directly to anthropic.messages.create(tools=tools, ...)
```

---

## What this unlocks for AI systems

| Problem | What this solves |
|---|---|
| AI model provenance is asserted, not proven | Model weights and eval results get permanent content-addressed identities |
| Scientific data is cite-by-URL (link rot) | Observations get CIDs — permanent and retrievable from any IPFS node |
| Multi-agent pipelines have no audit trail | Agent A certifies output → Agent B includes `uor_address` in its payload → verifiable provenance chain |
| RAG sources can't be verified | Every indexed chunk gets a `uor_address` — cite it alongside the embedding, prove it's unchanged |
| Credential verification requires the issuer | W3C VC + `uor-dag-cbor-2025` = offline-verifiable, cryptographically bound to content |

### Two-layer identity: content address + compact handle

The response carries two identity fields with distinct roles:

| Field | What it is | Changes when? |
|---|---|---|
| `@id` | `ipfs://<CID>` — full 32-byte SHA-256 multihash of the canonical payload, encoded in CIDv1 | Any byte change to the payload |
| `uor_address` | First 16 bytes of the same SHA-256, multibase base58btc — a compact, unique handle grounded in the UOR content-addressing namespace (`u:digest` / `u:canonicalBytes`) | Any byte change to the payload |

Both are fully deterministic: the same payload always produces the same `@id` and the same `uor_address`. `uor_address` is a shorter handle for use in agent memory, provenance chains, and knowledge graph nodes where a full CID URI is verbose.

The `certificate` field carries the UOR kernel's type-level admission proof — the `GroundingCertificate` attesting that the payload was processed by the `ConstrainedTypeInput` schema at Witt level W8. This is the kernel's structural invariant, separate from the per-object content address.

Practical consequence for an AI coding agent:

- Use `@id` as the **integrity anchor** — proves the exact bytes delivered to the user have not changed, verifiable from any IPFS node without trusting the agent or this service.
- Use `uor_address` as the **compact identity handle** — shorter than the full CID, unique per object, suitable as a memory key or provenance pointer in multi-agent pipelines.
- Use `certificate` to verify the object was admitted by the UOR kernel — the W3C VC projection (`?as=vc`) exposes this as an offline-verifiable credential.

---

## Standards

| Standard | How it's used |
|---|---|
| [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/) | Every certify response is a valid JSON-LD node |
| [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) | `digestMultibase` field; certificate carries a DI proof |
| [W3C VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | Certificate projects to a VC via `?as=vc` |
| [IPFS IPIP-402](https://specs.ipfs.tech/ipips/ipip-0402/) | Trustless block gateway; all blocks are content-addressed |
| [OpenAI function calling](https://platform.openai.com/docs/guides/function-calling) | `/v1/openai-tools` serves ready-to-use tool definitions |
| [UOR-Framework](https://github.com/UOR-Foundation/UOR-Framework) | Ontological kernel; `uor_address` is from the `state` namespace |

---

## Crate structure

| Crate | Role |
|---|---|
| [`sem-ipld`](crates/sem-ipld/) | Library — projects UOR-admitted values into IPLD + JSON-LD + SRI-2 |
| [`uor-vc-crypto`](crates/uor-vc-crypto/) | Two W3C Data Integrity 1.0 cryptosuites: unsigned + Ed25519-signed |
| [`sem-ipld-service`](crates/sem-ipld-service/) | HTTP service — the binary you deploy |

### Path dependency

All crates depend on [`uor-foundation`](https://github.com/UOR-Foundation/UOR-Framework). Clone it at the same level:

```
your-workspace/
├── sem-ipld-service/   ← this repo
└── UOR-Framework/
    └── foundation/
```

---

## Signing

| Cryptosuite | Proof | Use when |
|---|---|---|
| `uor-dag-cbor-2025` | CID of canonical form | Tamper-evidence; single writer |
| `uor-dag-cbor-ed25519-2025` | Ed25519 over CID multihash | Tamper-evidence + authenticity; multi-party |

Enable signing: set `SEM_IPLD_ISSUER_KEY_B64` on the service.  
Generate a key: `cargo run --release -p uor-vc-crypto --bin gen-issuer-key`

---

## Deploy

One-click Railway deploy: new project → this repo → **Settings → Volumes** → mount `/data` → **Generate Domain**.

Set `PUBLIC_BASE_URL=https://your-deployment.up.railway.app` so the AI plugin manifest resolves correctly.

Full walk-through: [`deploy/DEPLOY.md`](deploy/DEPLOY.md)

---

## License

Apache-2.0. See [LICENSE](LICENSE).
