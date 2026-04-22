# Trustless Object Identity — from Any Data, in One Call

Every naming system in use today requires a naming authority.

DNS needs registrars. DOIs need publishers. UUIDs are random — they carry no meaning. SHA-256 hashes are format-dependent: re-encode the same JSON document differently and you get a different hash. These systems name things by *location* or *assignment*. None of them name things by *what they are*.

This project changes that.

---

## What it does

POST any digital object to `POST /v1/certify`. You get back two identifiers:

**`uor_address`** — a compact, unique 128-bit handle for this object, derived from the first 16 bytes of its canonical SHA-256 digest and grounded in the UOR content-addressing namespace (`u:digest` / `u:canonicalBytes` per the [UOR-Framework](https://github.com/UOR-Foundation/UOR-Framework) spec). Shorter than a full CID — designed as a memory key, provenance pointer, and knowledge-graph node identifier for agent systems.

**`@id`** — `ipfs://<CID>` — the permanent, globally retrievable content address. The full 32-byte SHA-256 multihash in CIDv1 form. Resolves from any public IPFS node. No account, no API key, no dependency on this service.

**`certificate`** — `ipfs://<CID>` — the UOR kernel's admission proof. A `GroundingCertificate` attesting that the payload was processed by the `ConstrainedTypeInput` schema at Witt level W8. Projects to a W3C Verifiable Credential via `?as=vc`.

Together:

> *"This object was admitted by the UOR kernel, received a permanent content address, and the kernel's proof was issued as a W3C Verifiable Credential — all in a single atomic operation. Anyone, anywhere can retrieve and verify the object from any IPFS node without trusting you, the issuer, or any registry."*

No other system does all of that in a single atomic operation.

---

## The response

Every call returns a valid JSON-LD 1.1 document:

```json
{
  "@context": "https://uor.foundation/",
  "@type":    "https://uor.foundation/state/GroundedContext",
  "uor_address":  "z9Yrf1BFzxkMGXLmhzCxAivRPMBn3BwD",
  "@id":          "ipfs://bafyreic72oorcja3h7e7suwg3qgdnfbdpyti3dy54zcebifn535yvq2lbq",
  "certificate":  "ipfs://bafyreig3lqv5fblgr3vupfvzmxnbzq2xqrvqimhpjhbmxkynqpqcxpxhq4",
  "integrity":        "sha256-U0fJjNb+W0AcFFYQmbmBdjP44x+Gg6z6GnYf5O4YWno=",
  "digestMultibase":  "uEiArPBHXCiF2s4qwX4RCOcFujtR3WIwL53bBKjZnDCFaHg",
  "foundation_version": "0.3.0",
  "gateway": {
    "data":   "https://api.uor.foundation/v1/blocks/bafyrei…",
    "cert":   "https://api.uor.foundation/v1/blocks/bafyrei…",
    "jsonld": "https://api.uor.foundation/v1/blocks/bafyrei…?as=jsonld",
    "vc":     "https://api.uor.foundation/v1/blocks/bafyrei…?as=vc"
  }
}
```

`@id` and `certificate` are permanent. The `gateway` URLs are HTTP convenience — useful but not the source of truth.

---

## Ready to use right now

This service speaks the standards that AI agents already understand. No wrapper libraries. No custom SDKs.

**Any OpenAI-compatible agent** (LangChain, CrewAI, AutoGPT, AWS Bedrock, GPT-4, Claude) can call it as a native tool today:

```python
import requests, openai

tools = requests.get("https://api.uor.foundation/v1/openai-tools").json()
openai.chat.completions.create(model="gpt-4o", tools=tools, messages=[...])
```

The tool manifest is at `/.well-known/ai-plugin.json`. The OpenAPI spec is at `/v1/openapi.yaml`. Any framework that reads OpenAPI auto-discovers every operation.

---

## What this unlocks for AI systems

**An AI agent certifying its own outputs**

A coding agent generates a function. Before returning it, it calls `certify`. The response `@id` goes into the commit message. Six months later, anyone can prove that exact function was produced on that date — without trusting the agent, the developer, or any log system.

**Decentralized agent memory**

An agent stores an observation by certifying it. The `uor_address` is the pointer. It travels with the agent across sessions, across machines, across providers. Anyone with that `uor_address` can retrieve the exact bytes from any IPFS node and verify they are unchanged.

**Multi-agent provenance chains**

Agent A certifies a dataset — returns `uor_address_A`. Agent B certifies its analysis, embedding `uor_address_A` in the payload. The result is a verifiable provenance chain where any auditor can reconstruct the full pipeline from the IPFS block graph, with no dependency on the agents, their logs, or any central system.

**LLM output verification**

A user asks: "Did the AI produce this document, or was it tampered with?" The `integrity` field is `sha256-<base64>` — drop it into any browser `<link>` integrity check. The `certificate` is a W3C Verifiable Credential. Anyone verifies offline without calling the issuer.

**Semantic web agents**

The response is a valid JSON-LD node. A knowledge graph agent ingests it directly into a triple store. `uor_address` becomes a stable node identifier. `certificate` links to a VC that any DID resolver can verify. This is the semantic web — not aspirational, but working.

**RAG pipelines with verifiable provenance**

Every document chunk is certified before indexing. `uor_address` travels alongside the embedding in the vector store. When the LLM cites a source, it includes the `@id` — a cryptographic proof that the chunk has not changed since it was indexed.

---

## Why the composition matters

IPFS does content addressing. W3C does Verifiable Credentials. JSON-LD does semantic typing. Each of these existed before this project.

What is new is the *composition*: a single API call crosses all three standards simultaneously, anchored by a formal admission kernel that gives objects semantic identity — not just byte identity. The `wittBits` in the certificate are not cosmetic. They implement, literally, the Wittgenstein insight that every proposition has a determinate logical form that shows its structure. The UOR kernel assigns a Wittgenstein signature to every admitted object. This is the grounding problem — connecting symbols to real-world referents — solved at the infrastructure layer.

The closest analogy: Bitcoin did not invent cryptography or peer-to-peer networks. It composed them in a way that made trustless value transfer possible for the first time. This project composes content addressing, semantic identity, and verifiable credentials in a way that makes *trustless object identity* possible for the first time.

---

## Standards implemented

| Standard | Role |
|---|---|
| [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/) | Response is a valid JSON-LD node — parseable by any processor |
| [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) | `digestMultibase`; certificate carries a DI proof |
| [W3C VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | Certificate projects to a Verifiable Credential via `?as=vc` |
| [IPFS IPIP-402](https://specs.ipfs.tech/ipips/ipip-0402/) | Trustless block gateway; immutable, content-addressed |
| [OpenAI function calling](https://platform.openai.com/docs/guides/function-calling) | `/v1/openai-tools` — ready-to-use for any OpenAI-compatible agent |
| [GPT Actions](https://platform.openai.com/docs/actions) | `/.well-known/ai-plugin.json` — discoverable by ChatGPT and compatible platforms |
| [UOR-Framework](https://github.com/UOR-Foundation/UOR-Framework) | Ontological kernel; `uor_address` is from the `state` namespace |

---

## Get started

**Live API:** `https://api.uor.foundation`

**Source:** [github.com/UOR-Foundation/sem-ipld-service](https://github.com/uor-foundation/sem-ipld-service)

**Interactive docs:** [Swagger UI](https://petstore.swagger.io/?url=https://api.uor.foundation/v1/openapi.yaml)

```bash
curl -X POST https://api.uor.foundation/v1/certify \
     -H 'Content-Type: application/json' \
     -d '{"your": "data", "goes": "here"}'
```

No account. No API key. No registry. Permissionless.
