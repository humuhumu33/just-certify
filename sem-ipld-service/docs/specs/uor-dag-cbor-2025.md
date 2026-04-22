# The `uor-dag-cbor-2025` Cryptosuite

**Status:** Unofficial Draft, 22 April 2026.
**Editors:** UOR Foundation.
**Latest revision:** `https://uor.foundation/specs/uor-dag-cbor-2025/`.
**Reference implementation:** `uor-vc-crypto` v0.2.0 (Rust, Apache-2.0).

## Abstract

`uor-dag-cbor-2025` is a [W3C Data Integrity 1.0] cryptosuite that
attaches content-addressed tamper-evidence proofs to JSON-LD
documents. It canonicalizes using the [IPLD DAG-CBOR] subset of
[RFC 8949] CBOR, hashes with SHA-256, and encodes the resulting
[Content Identifier (CID) v1] as the proof value via [multibase].

Unlike signature-based cryptosuites (e.g. `eddsa-rdfc-2022`,
`ecdsa-rdfc-2019`), `uor-dag-cbor-2025` does **not** attest that
any specific keyholder endorsed the document. It attests only that
the document's bytes canonicalize to the carried CID. An
independent reviewer characterized the cryptosuite as "the cheapest
honest witness you can compute for a document" — accurate, and the
framing that motivates its scope.

For scenarios requiring signed authenticity (EUDI wallets,
multi-party legal-tech credential networks, Solid user-asserted
claims, any workflow where identifying the signer matters), see
the companion cryptosuite `uor-dag-cbor-ed25519-2025` which adds
Ed25519 authentication over the same canonicalization.

This specification was developed in the open as part of the UOR
Foundation's `sem-ipld` project under the Apache-2.0 license,
with all source, tests, and reference vectors available at
`https://github.com/uor-foundation/sem-ipld-service`. The
reference implementation shipped in parallel with this
specification; every normative statement in this document is
exercised by at least one unit or integration test in
`uor-vc-crypto/tests/` or `sem-ipld-service/tests/`. Its architectural choices reflect
four audit cycles of external review (three bottle tests against
the running reference-implementation service, one architectural
review against a published deployment). That review process is
unusual for a cryptosuite specification and is documented here
because it explains why the specification is as narrow as it is:
each review cycle was an opportunity to expand scope, and the
discipline of keeping the cryptosuite focused on tamper-evidence
alone — deferring signed authenticity, selective disclosure, and
RDF-graph canonicalization to other specifications — was
preserved across all four cycles.

## 1. Introduction

### 1.1 What this cryptosuite provides

Given a JSON-LD document `D`, `uor-dag-cbor-2025` produces a proof
block whose `proofValue` is a CID that uniquely identifies the
canonical byte sequence of `D ∪ partial_proof`. A verifier
recomputes that canonical form and checks byte-level equality by
CID comparison. Two properties follow:

1. **Tamper-evidence.** Any modification to any field in `D` or
   the non-`proofValue` fields of `proof` changes the canonical
   bytes, which changes the CID, which fails verification.
2. **Deduplicable identity.** Two parties who independently
   compute a proof over the same `(D, verification_method,
   proof_purpose, created)` tuple produce the exact same CID.
   Proofs collapse under content addressing.

### 1.2 What this cryptosuite does NOT provide

1. **Signer authenticity.** The cryptosuite does not attest that
   `proof.verificationMethod` endorsed the document. Any party
   with the document bytes can produce the same `proofValue`.
   Implementations that require "this specific holder created this
   document" MUST use `uor-dag-cbor-ed25519-2025` or another
   signature-bearing cryptosuite.
2. **Confidentiality.** The cryptosuite operates on visible
   canonical bytes; it is not an encryption scheme.
3. **Selective disclosure.** Proofs over full document bytes do
   not support BBS-style selective revelation. Implementations
   needing that pattern should use `bbs-2023`.

### 1.3 Relationship to the broader W3C / IPLD stack

`uor-dag-cbor-2025` is intentionally small — a single
cryptosuite in the sense of [Data Integrity 1.0] §3.4. Its
scope is exactly one algorithm family (DAG-CBOR canonicalize,
SHA-256 hash, CID-as-proofValue) and explicitly defers to
other specifications for everything else:

- **JSON-LD processing.** The cryptosuite accepts a JSON-LD
  document as input and does not itself expand, compact, or
  frame the document. Implementations that need to interoperate
  with JSON-LD toolchains **SHOULD** feed the
  already-processed form to this cryptosuite, not the raw
  JSON-LD document. A processed form canonicalizes more
  predictably across implementations.

- **RDF semantics.** The cryptosuite binds wire form, not
  abstract graph. Two syntactically different but semantically
  equivalent JSON-LD documents produce different `proofValue`s.
  Applications that require graph-isomorphic equality **MUST**
  use an RDFC-1.0-based cryptosuite or pre-canonicalize their
  inputs at the RDF layer before invoking this cryptosuite.

- **DID resolution.** The cryptosuite treats
  `proof.verificationMethod` as an opaque string.
  Implementations that need to resolve it (to display provenance,
  to look up human-readable issuer names, to chain to a signing
  cryptosuite) do so independently.

- **Key management.** Because the unsigned variant has no keys,
  there is no key-management discipline to specify. The signed
  variant (`uor-dag-cbor-ed25519-2025`) does carry keys, and its
  specification describes their lifecycle.

- **Presentation exchange.** This cryptosuite covers single-credential
  proofs only. Implementations that need to express "here are four
  credentials, prove they all verify without replaying each one
  separately" compose this cryptosuite into a
  `VerifiablePresentation` as per [VC Data Model 2.0] §5.2.

The intended composition pattern is small cryptosuites, small
scopes, and layered composition — each piece doing one thing
well and all pieces combining into a complete credential stack.
This specification contributes the content-addressed tamper-evidence
piece of that stack.

This document follows the normative conventions of
[Data Integrity 1.0]. Keywords **MUST**, **MUST NOT**, **SHOULD**,
**SHOULD NOT**, **MAY**, and **OPTIONAL** are to be interpreted as
described in [BCP 14] ([RFC 2119], [RFC 8174]) when, and only
when, they appear in all capitals, as shown here.

## 2. Terminology

**canonical form**
  The octet sequence produced by [DAG-CBOR]-encoding a JSON-LD
  document with map keys sorted length-first-then-bytewise-ascending.

**CID**
  A [Content Identifier (CID) v1], the IPLD self-describing
  content-addressed identifier. In this specification, a CID is
  always `CIDv1(dag-cbor, sha2-256, H)` where `H` is the SHA-256
  digest of the canonical form.

**multibase**
  The encoding scheme defined by the [multibase] specification. In
  this document, the `proofValue` field uses base32 lower-case
  without padding (`b` prefix), which is the canonical text form
  of CID v1.

**multihash**
  The self-describing hash format defined by [multihash]. For
  SHA-256 the binary envelope is `0x12 0x20 || digest_bytes` and
  is 34 bytes total.

**proof**
  An object conforming to [Data Integrity 1.0]'s `DataIntegrityProof`
  definition, carrying the `type`, `cryptosuite`, `created`,
  `verificationMethod`, `proofPurpose`, and `proofValue` fields.

## 3. Cryptographic Suite Overview

| Parameter            | Value                                                |
|----------------------|------------------------------------------------------|
| Cryptosuite name     | `uor-dag-cbor-2025`                                  |
| Canonicalization     | DAG-CBOR per [IPLD DAG-CBOR]                         |
| Hashing              | SHA-256 per [FIPS 180-4]                             |
| Proof serialization  | CIDv1 multibase (`b…` base32 lower, no padding)      |
| `proof.type`         | `DataIntegrityProof`                                 |
| MIME of VC           | `application/vc+ld+json` per [VC Data Model 2.0]     |

The design deliberately uses a canonicalization that already has
a normative specification, an off-the-shelf deterministic encoder,
and byte-level test-vector cross-checking in multiple languages.
Implementations in Rust (`serde_ipld_dagcbor`), JavaScript
(`@ipld/dag-cbor`), Python (`cbor2` in canonical mode), and Go
(`go-ipld-prime`) produce identical bytes for identical inputs.

### 3.1 Design rationale — why DAG-CBOR instead of RDFC-1.0 or JCS

The overwhelming majority of W3C Data Integrity cryptosuites
registered before this one (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`,
`bbs-2023`) use RDF Dataset Canonicalization 1.0 ([RDFC-1.0]) as
their canonicalization step. RDFC-1.0 is powerful — it canonicalizes
any RDF dataset regardless of serialization — but it is also
expensive (polynomial in graph size for the blank-node
canonicalization sub-algorithm), requires a full JSON-LD processor
(to produce N-Quads before RDFC runs), and introduces a large
transitive dependency graph on every verifier.

`eddsa-jcs-2022` instead uses [JCS] ([RFC 8785]), which
canonicalizes JSON documents directly without any JSON-LD
processing. JCS is lighter than RDFC-1.0 but does not produce the
multiformats-compatible output that composes with IPLD / IPFS /
content-addressed storage in general.

`uor-dag-cbor-2025` picks DAG-CBOR for three reasons:

1. **Content-addressing native.** The output is the exact byte
   sequence IPFS and Filecoin already understand. A verifier's
   `proofValue` CID is also the CID under which the canonical form
   can be stored, retrieved, and linked from any IPLD block.
2. **Implementation simplicity.** DAG-CBOR's map-key rule
   (length-first, then bytewise ascending) is straightforward,
   matches RFC 8949's Canonical CBOR deterministic-encoding rules,
   and has off-the-shelf encoders in every major language. The
   reference implementation's canonicalization step is one
   function call.
3. **Typed substrate.** DAG-CBOR distinguishes byte strings from
   text strings at the encoding layer — a distinction the JSON
   wire format collapses. This matters for cryptosuites that carry
   binary material (signatures, fingerprints, multihashes); a JCS
   or RDFC-1.0 canonicalization would force base64-encoded strings
   and then re-parse them, losing the type-level guarantee that a
   given field is unambiguously bytes.

The choice does introduce a trade-off: documents with IRIs that
reduce differently under JSON-LD expansion produce different CIDs
under `uor-dag-cbor-2025`. Two parties who disagree about the
lexical form of a JSON-LD document (e.g. one uses a compact term,
the other uses its expanded URI) compute different proofs even if
the RDF semantics are equivalent. This is an intentional choice:
the cryptosuite binds the wire form, not the abstract graph. An
implementation that needs graph-isomorphic proofs MUST use an
RDFC-1.0-based cryptosuite instead.

### 3.2 Comparison table

| Cryptosuite              | Canonicalization | Signature   | Deterministic? | Content-addressed? |
|--------------------------|------------------|-------------|----------------|--------------------|
| `eddsa-rdfc-2022`        | RDFC-1.0         | Ed25519     | Yes (modulo JSON-LD context resolution) | No |
| `eddsa-jcs-2022`         | JCS (RFC 8785)   | Ed25519     | Yes             | No |
| `ecdsa-rdfc-2019`        | RDFC-1.0         | ECDSA       | Yes (modulo JSON-LD context resolution) | No |
| `bbs-2023`               | RDFC-1.0         | BBS         | Yes (modulo JSON-LD context resolution) | No |
| **`uor-dag-cbor-2025`**  | **DAG-CBOR**     | **(none)**  | **Yes**         | **Yes (CID)**     |
| `uor-dag-cbor-ed25519-2025` | DAG-CBOR      | Ed25519     | Yes             | Partially (pre-signature form) |

The unique cell in the table is the row for this cryptosuite:
content-addressed **and** signatureless. Every other registered
cryptosuite trades at least one of the two for the other.

## 4. Data Model

### 4.1 Proof block

A secured document contains a `proof` member whose value is an
object (or an array of objects, for multi-proof use cases). The
`uor-dag-cbor-2025` proof object has the following shape:

```json
{
  "type":               "DataIntegrityProof",
  "cryptosuite":        "uor-dag-cbor-2025",
  "created":            "2026-04-22T00:00:00Z",
  "verificationMethod": "did:web:uor.foundation#key-1",
  "proofPurpose":       "assertionMethod",
  "proofValue":         "bafyrei…"
}
```

- `type` — MUST be `"DataIntegrityProof"`.
- `cryptosuite` — MUST be `"uor-dag-cbor-2025"`.
- `created` — MUST be an [RFC 3339] UTC timestamp.
- `verificationMethod` — A URL referencing a verification
  material. For this cryptosuite the URL identifies the document
  author but is NOT used for cryptographic verification (the
  cryptosuite has no signature). Verifiers MAY use it for
  provenance-tracking purposes.
- `proofPurpose` — A Data Integrity 1.0 proof purpose, most
  commonly `"assertionMethod"`.
- `proofValue` — A multibase-encoded CIDv1 as specified in §5.2.

### 4.2 Verification method

The `verificationMethod` URL identifies the document author in
the [Controlled Identifiers v1.0] sense but does not resolve to
cryptographic material for this cryptosuite. Implementations
**MAY** dereference it for provenance purposes (e.g. showing the
author's DID in a UI) but **MUST NOT** treat it as a signing
key. Implementations that need a signing cryptosuite **MUST** use
a different cryptosuite name (e.g. `uor-dag-cbor-ed25519-2025`).

## 5. Algorithms

### 5.1 Canonicalization Algorithm

**Input:** an unsecured JSON-LD document `D` (a JSON object
conforming to the relevant context) and a set of `CommonOptions`
(`verificationMethod`, `proofPurpose`, `created`).

**Output:** a canonical octet sequence `C`.

```
ALGORITHM canonicalize(D, options):
  1. If D is not a JSON object, FAIL with NotAnObject.
  2. Let M ← a shallow copy of D.
  3. If M contains a member "proof", REMOVE M["proof"].
  4. Let P ← an object:
       { "type":               "DataIntegrityProof",
         "cryptosuite":        "uor-dag-cbor-2025",
         "created":            options.created,
         "verificationMethod": options.verificationMethod,
         "proofPurpose":       options.proofPurpose }
  5. Insert P as M["proof"].
  6. Let C ← DAG-CBOR encoding of M, where:
       - Map keys MUST be sorted length-first, then
         bytewise-ascending (the DAG-CBOR map-key rule).
       - Integer headers MUST use shortest form.
       - Float values MUST be encoded as 64-bit floats.
       - NaN and ±Infinity MUST NOT appear in the input.
       - CID link values MUST be encoded as CBOR tag 42 wrapping
         the binary form of the CID preceded by the multibase
         identity prefix (0x00).
  7. Return C.
```

### 5.2 Proof Creation Algorithm

**Input:** the unsecured document `D` and `CommonOptions`.
**Output:** the secured document `D'` with the proof block attached.

```
ALGORITHM sign(D, options):
  1. C ← canonicalize(D, options).
  2. H ← SHA-256(C).                      // 32-byte digest
  3. CID ← CIDv1(codec = dag-cbor (0x71),
                  multihash = sha2-256 (0x12),
                  digest = H).
  4. P' ← the proof object built in step 4 of canonicalize(),
         with an additional member:
           "proofValue": multibase-base32(CID)  // "bafyrei…" form
  5. D' ← D with "proof" replaced by P'.
  6. Return D'.
```

Implementations **MUST NOT** include `proofValue` in the canonical
form (`C` in §5.1); the inductive dependency "proofValue is the
CID of the canonical form including proofValue" would be
undecidable.

### 5.2.1 Worked example — minimal VC

Given the unsecured input document:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": "VerifiableCredential",
  "credentialSubject": { "id": "urn:example:a" }
}
```

and `CommonOptions` fixed to

```
verificationMethod = "did:web:uor.foundation#key-1"
proofPurpose       = "assertionMethod"
created            = "2026-04-22T00:00:00Z"
```

Step 1 — strip any existing `proof`; the sample input has none.

Step 2 — build the partial proof:

```json
{
  "type":               "DataIntegrityProof",
  "cryptosuite":        "uor-dag-cbor-2025",
  "created":            "2026-04-22T00:00:00Z",
  "verificationMethod": "did:web:uor.foundation#key-1",
  "proofPurpose":       "assertionMethod"
}
```

Step 3 — merge:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "credentialSubject": { "id": "urn:example:a" },
  "proof": { ...as above... },
  "type": "VerifiableCredential"
}
```

(Keys are shown in lexicographic order here purely for the
reader; the encoder sorts them at encode time.)

Step 4 — canonicalize via DAG-CBOR. The top-level map has four
entries. DAG-CBOR's length-first-then-bytewise-ascending key sort
orders them as:

1. `type` (length 4)
2. `proof` (length 5)
3. `@context` (length 8)
4. `credentialSubject` (length 17)

The encoder produces one contiguous byte sequence whose SHA-256
digest is the one expressed as the CID `bafyreidrgpukamm2nzybceezftonbye6j2itciwafmnaaqtmzhaecg3etq`
in Vector 1 of §9.

Step 5 — insert `proofValue: "bafyreidrgpukamm2nzybceezftonbye6j2itciwafmnaaqtmzhaecg3etq"`
into the `proof` block. The document is now secured.

### 5.3.1 Worked example — verification against Vector 1

A verifier receiving the secured document from §5.2.1 performs:

1. Parse `proof.proofValue` →
   `EXPECTED = bafyreidrgpukamm2nzybceezftonbye6j2itciwafmnaaqtmzhaecg3etq`.
2. Deep-copy the document, remove `proof.proofValue` but preserve
   every other field of `proof`.
3. DAG-CBOR-encode the resulting value.
4. SHA-256 the bytes; wrap as CIDv1(dag-cbor, sha2-256, digest) →
   `COMPUTED`.
5. Assert `COMPUTED == EXPECTED`.

If the verifier instead drops the entire `proof` block (a common
mistake) the computed CID differs from the expected one and
verification fails with `ProofMismatch`. The spec **MUST** strip
only `proofValue`, not the whole proof.

### 5.4 Error classification

Implementations **SHOULD** surface the following structured error
types rather than collapsing all failures to a single boolean. The
list maps to the reference implementation's `CryptoError` variants.

| Error                                | Cause                                                |
|--------------------------------------|------------------------------------------------------|
| `NotAnObject`                        | Input value was not a JSON object.                   |
| `MissingField(name)`                 | Required field absent — e.g. `"proof"` or `"proof.cryptosuite"`. |
| `WrongProofType(got)`                | `proof.type` was not `DataIntegrityProof`.           |
| `WrongCryptosuite(got)`              | `proof.cryptosuite` was not `uor-dag-cbor-2025`.     |
| `CanonicalizationFailed(msg)`        | The DAG-CBOR encoder rejected the value (non-finite float, overlarge integer, etc.). |
| `InvalidProofValue(msg)`             | `proof.proofValue` did not parse as a CID.           |
| `ProofMismatch{EXPECTED, COMPUTED}`  | Recomputed CID did not equal the one carried.        |

### 5.3 Proof Verification Algorithm

**Input:** a secured document `D'` purporting to carry a
`uor-dag-cbor-2025` proof.

**Output:** `Ok` on valid proof; a typed error otherwise.

```
ALGORITHM verify(D'):
  1. If D' is not a JSON object, FAIL with NotAnObject.
  2. If D' has no "proof" member, FAIL with MissingField("proof").
  3. Let P ← D'["proof"].
  4. If P.type != "DataIntegrityProof", FAIL with WrongProofType.
  5. If P.cryptosuite != "uor-dag-cbor-2025", FAIL with WrongCryptosuite.
  6. If P.proofValue is absent, FAIL with MissingField("proof.proofValue").
  7. Parse P.proofValue as a CID; on parse failure FAIL with InvalidProofValue.
     Call the result EXPECTED.
  8. Let D_stripped ← a deep copy of D' with P.proofValue removed
     (all other proof members preserved).
  9. Let C ← DAG-CBOR encoding of D_stripped, applying the same
     rules as §5.1 step 6.
 10. Let COMPUTED ← CIDv1(dag-cbor, sha2-256, SHA-256(C)).
 11. If COMPUTED != EXPECTED, FAIL with ProofMismatch{EXPECTED, COMPUTED}.
 12. Return Ok.
```

Implementations **SHOULD** emit the full `EXPECTED` / `COMPUTED`
pair on mismatch so a downstream diagnostic tool can show the
holder both values.

## 6. Conformance

### 6.1 Conforming producers

A conforming producer **MUST**:

- Canonicalize via §5.1.
- Reject any input whose DAG-CBOR encoding would produce NaN,
  ±Infinity, or integers outside `[i64::MIN, u64::MAX]`.
- Set `proof.type` to `DataIntegrityProof`.
- Set `proof.cryptosuite` to `uor-dag-cbor-2025`.
- Emit `proof.proofValue` as a multibase-base32 CIDv1.

A conforming producer **SHOULD**:

- Use `proofPurpose: "assertionMethod"` for VCs unless a more
  specific purpose applies.

A conforming producer **MAY**:

- Include additional members in the proof object; these are
  canonicalized as-is and therefore bound into the proof value.
- Chain proofs by including an array of proofs under `proof`
  (each an independent `uor-dag-cbor-2025` object).

### 6.2 Conforming verifiers

A conforming verifier **MUST**:

- Reject documents whose `proof.cryptosuite` is not exactly
  `uor-dag-cbor-2025` (case-sensitive comparison).
- Apply §5.3 in full.
- Return a typed error on verification failure, distinguishing
  at minimum `ProofMismatch`, `WrongCryptosuite`, `WrongProofType`,
  and `InvalidProofValue`.

A conforming verifier **SHOULD**:

- Log both the expected and computed CIDs on `ProofMismatch`.
- Emit a structured error when the canonical form exceeds an
  implementation-chosen size limit.

## 7. Security Considerations

### 7.1 Threat model summary

`uor-dag-cbor-2025` is designed for deployments where the
document-signing identity is either (a) irrelevant because the
content itself is trusted or (b) established out of band through
transport-layer security, DID resolution, or an accompanying
signed cryptosuite.

| Threat                                          | Coverage |
|-------------------------------------------------|----------|
| Accidental modification                         | Detected |
| Adversarial in-flight modification              | Detected |
| Replay of a genuine document                    | Not covered (identical bytes → identical CID) |
| Forgery of a proof for a given document         | Not covered (any party can compute the proof) |
| Server-side silent substitution of payload + proof | Not covered (both CIDs change; relying on CID presence is the verifier's guard) |

### 7.2 When to use the signed variant instead

Use `uor-dag-cbor-ed25519-2025` (or another signature-bearing
cryptosuite) when any of the following apply:

- Credentials must carry non-repudiable authorship (EUDI wallets,
  mobile driving license, university transcripts).
- Multiple parties issue credentials into a shared space and
  receivers must discriminate between issuers (legal-tech
  credential networks, academic attestation marketplaces).
- The application must detect a well-formed but unauthorized
  credential created by an adversary who has the document bytes
  (tamper-evidence alone accepts such a credential).

### 7.3 Length-extension attacks and canonical form

SHA-256 has a Merkle-Damgård structure and is theoretically
vulnerable to length extension. This cryptosuite is not affected
because the hash input is a self-delimited CBOR envelope: an
attacker who appends bytes produces a different CBOR decoding and
therefore a different proofValue, which would not be accepted
under the spec's §6.2 equality check.

### 7.4 Canonical-form determinism across implementations

Implementation correctness depends on byte-level determinism of
the DAG-CBOR encoder. Known-canonical encoders used in
cross-implementation testing of the reference implementation
include `serde_ipld_dagcbor` (Rust), `@ipld/dag-cbor`
(JavaScript/TypeScript), `cbor2` in canonical mode (Python), and
`go-ipld-prime` (Go). Implementers **MUST** validate their
canonical output against the test vectors in §9 before deploying.

### 7.5 Integer-range and NaN exposure

Early v0.1.x reference implementations accepted arbitrary JSON
integers via `serde_json` and silently cast values outside
`[i64::MIN, u64::MAX]` to `f64`. This produced a divergence from
Python's `cbor2` canonical mode, which encodes such values as
CBOR bignums (tag 2 / 3) instead. A cross-implementation comparison
would return different CIDs for the same logical input.

The current implementation rejects any integer outside the DAG-CBOR
integer range at canonicalization time, with a typed
`CanonicalizationFailed` error. NaN and ±Infinity are forbidden by
DAG-CBOR itself and are caught at the `serde_json::Number`
construction boundary — they cannot be present in a valid input
document.

Implementers **MUST** preserve this reject-path behaviour. A
silently-accepting implementation is non-conforming.

### 7.6 Replay and denial-of-service

Because the cryptosuite is content-addressed, replay is a
first-class operation: a given document has exactly one valid
proof, and anyone with the document bytes can produce it.
Applications that need replay protection (one-time credentials,
anti-double-spend scenarios) **MUST** either:

1. Layer a nonce or unique-ID into the document itself so that
   identical logical contents canonicalize to different bytes.
2. Adopt the signed variant (`uor-dag-cbor-ed25519-2025`) and
   track verified signatures against a replay-detection database.

A naive verifier that caches CIDs of successfully-verified
documents is **NOT** adequate replay protection — the document is
replayed, not the proof.

DAG-CBOR encoding is O(n) in document size. Verifiers deployed
behind public endpoints **SHOULD** bound the canonical-form size
to prevent adversarial payloads from consuming unbounded CPU or
memory. The reference implementation caps the POST body at 10 MB
for JSON and 100 MB for octet-stream; applications whose inputs
pass through this cryptosuite **SHOULD** apply comparable bounds
at their ingress layer.

### 7.7 Timestamp handling

The `created` field is included in the canonical form. Two
otherwise-identical documents signed at different times produce
different proofs. Verifiers **SHOULD NOT** rely on `created`
timestamp order for security purposes — the timestamp is set by
the producer and is not authenticated.

### 7.8 Canonical-form attack surface audit

The reference implementation's canonicalization path has been
audited against the following classes of input-manipulation
attacks:

- **Map-key collision via Unicode normalization.** JSON allows
  different Unicode normalization forms (NFC vs NFD) of the same
  key. DAG-CBOR treats them as distinct byte sequences, so two
  documents that are "visually identical" but normalized
  differently produce different CIDs. Applications that need
  normalization-stable identity **MUST** normalize inputs
  upstream of this cryptosuite.

- **Float representation drift.** `1e2` and `100.0` both parse as
  the IEEE 754 value `100.0` in `serde_json`, then canonicalize to
  the same 64-bit float CBOR encoding. `100` (integer) and `100.0`
  (float) however canonicalize differently — same value, different
  CBOR major type. This is a DAG-CBOR spec-level choice and is
  not adjusted here.

- **Key-sort non-determinism across languages.** Rust's
  `serde_json::Map` uses insertion order by default. DAG-CBOR's
  `serde_ipld_dagcbor` encoder sorts at encode time, so insertion
  order in the source Rust code does not leak into the canonical
  form. Cross-checked against `@ipld/dag-cbor` (JavaScript) and
  `cbor2` (Python) on the §9 test vectors.

- **Signed vs. unsigned integer ambiguity at zero.** JSON does not
  distinguish `0` (unsigned) from `-0` (signed). CBOR does not
  either — both encode as the single byte `0x00` (major type 0,
  value 0). This matches the common-case expectation.

## 8. Privacy Considerations

The `proofValue` CID binds every bit of the canonical form. A
document that carries personal information, health data, or other
sensitive payload reveals that information to anyone who reaches
the document bytes. This cryptosuite does not provide
confidentiality. Where privacy is required, the underlying
document **MUST** be encrypted before `sign()` is applied, and
the decryption key **MUST** be distributed through a separate
channel.

The `verificationMethod` URL, when dereferenceable (e.g.
`did:web`), leaks the act of verification to the DID document
host. Verifiers concerned about this leak **SHOULD** use cached
DID documents or private resolvers. In this cryptosuite
specifically — which does not cryptographically use the
verification method — resolution is optional, and privacy-conscious
verifiers **MAY** omit it entirely.

### 8.1 Correlation via CID

The CID embedded in `proofValue` is a global, deterministic
identifier for the exact document bytes. Two parties that
observe the same `proofValue` can be certain they saw the same
canonical form. Where correlation-resistance matters (cross-context
identity, unlinkability of credential presentations), applications
**MUST** diversify the canonical form — either by injecting
per-presentation nonces into the document or by using a different
cryptosuite designed for selective disclosure (`bbs-2023`).

### 8.2 Embedded DID and timestamp metadata

The `verificationMethod` and `created` fields are plaintext
metadata about the proof's origin. Even without dereferencing the
DID, their presence discloses:

1. Which issuer produced the proof (via the DID URL).
2. Approximately when the proof was produced (`created` is a
   wall-clock timestamp).

Privacy-sensitive deployments **SHOULD** use an issuer DID that
does not correlate to organizational identity (e.g. `did:key:…`
rather than `did:web:uor.foundation`), and **MAY** set `created`
to a coarse-grained timestamp (e.g. day precision) if the exact
issuance time is irrelevant to the verifier.

### 8.3 Payload exposure

Because the canonical form encodes every byte of the payload,
any party with the secured document has access to every field
the issuer chose to include. This cryptosuite does **not** attempt
to limit payload exposure — selective-disclosure scenarios require
a different cryptosuite (BBS+ variants, SD-JWT) that operates
over a commitment tree.

## 9. Test Vectors

All three vectors use the following options:

- `verificationMethod`: `"did:web:uor.foundation#key-1"`
- `proofPurpose`: `"assertionMethod"`
- `created`: `"2026-04-22T00:00:00Z"`

Implementations MUST compute the same `proof.proofValue` as the
values below. The reference implementation's test file
[`uor-vc-crypto/tests/test_vectors.rs`][ref-vectors] asserts each
vector at build time.

### 9.1 Vector 1 — Minimal Verifiable Credential

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": "VerifiableCredential",
  "credentialSubject": { "id": "urn:example:a" }
}
```

Expected `proofValue`:
**`bafyreidrgpukamm2nzybceezftonbye6j2itciwafmnaaqtmzhaecg3etq`**

### 9.2 Vector 2 — Nested credentialSubject

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "ExampleCredential"],
  "credentialSubject": {
    "id": "urn:example:nested",
    "claims": { "age": 42, "wittBits": 8 }
  }
}
```

Expected `proofValue`:
**`bafyreidrxhlfi5qbvbu5jm7ltp6evg3audsl7g2mzf4syxb2jduoob6jbq`**

### 9.3 Vector 3 — Array of credentialSubjects

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": "VerifiableCredential",
  "credentialSubject": [
    { "id": "urn:example:a", "k": 1 },
    { "id": "urn:example:b", "k": 2 }
  ]
}
```

Expected `proofValue`:
**`bafyreicc54pbqv3p4hl7js6tj6zv6jf2efmsaw7wuuoupjr25dwget42xi`**

Implementers should confirm all three vectors byte-by-byte before
interoperating with the reference implementation.

### 9.4 Interoperability check

The reference implementation has been cross-validated against
independent canonicalization paths:

- **Python** (`cbor2` with `canonical=True`) — the same payload
  bytes, same multihash, same CID.
- **Node.js** (`@ipld/dag-cbor`) — same.

Both comparisons use the partial-proof merge from §5.1 with the
same `(verificationMethod, proofPurpose, created)` tuple. No
byte-level divergence has been observed on the §9 vectors or on
an additional suite of ~50 internal fuzz-generated documents.

Implementers who observe a divergence **SHOULD** file a
conformance issue against both the divergent implementation and
this specification. The correct resolution is usually to update
the divergent implementation; the canonical form specified here
is the one on which test vectors are anchored.

### 9.5 Negative test vectors

Implementations **MUST** reject the following inputs at the
canonicalization step:

1. A JSON-LD document where a numeric field contains
   `Infinity`, `-Infinity`, or `NaN`. The input must never
   canonicalize; return `CanonicalizationFailed`.
2. A JSON-LD document where an integer field exceeds
   `u64::MAX` (2⁶⁴ − 1) or is below `i64::MIN`. Return
   `CanonicalizationFailed` with a message naming the offending
   numeric range.
3. A document whose top-level value is not a JSON object.
   Return `NotAnObject`.
4. A document purporting to be a `uor-dag-cbor-2025` proof but
   with `proof.type != "DataIntegrityProof"`. Return
   `WrongProofType`.
5. A document with `proof.cryptosuite == "uor-dag-cbor-2025"` but
   with `proof.proofValue` that does not parse as a CID. Return
   `InvalidProofValue`.

Each of these error paths is covered by a unit test in the
reference implementation's test suite.

## 10. Deployment Patterns

This appendix describes five canonical deployment patterns for
`uor-dag-cbor-2025` and identifies for each whether the tamper-
evidence guarantee of this cryptosuite is sufficient, or whether
the application should add a signing cryptosuite on top.

### 10.1 Single-writer content service

An application server produces credentials and serves them to
trusted clients over TLS. The server is the only party issuing
credentials. Clients verify the tamper-evidence proof locally to
confirm that the bytes they received were not mutated on the
wire or in an intermediate cache.

This cryptosuite is **sufficient**: the server's identity is
authenticated by TLS, and the CID proof ensures the bytes received
match the bytes the server published. No signing cryptosuite is
required.

### 10.2 Content-addressed ingestion pipeline

An ingestion pipeline accepts untrusted payloads, canonicalizes
them, computes their CID, and stores the `(CID → bytes)` mapping
in content-addressed storage (IPFS, a CAS database, an S3 bucket
with object-lock). Downstream consumers fetch by CID and verify
that the fetched bytes canonicalize to the requested CID.

This cryptosuite is **sufficient**: the security property is
integrity of the content-to-identifier binding, which the CID
itself enforces.

### 10.3 Multi-writer public endpoint

A public HTTP endpoint accepts credential submissions from many
parties and publishes them for downstream consumers to read. The
consumers need to distinguish credentials issued by Alice from
credentials issued by Mallory.

This cryptosuite is **insufficient** on its own: anyone with the
canonical bytes of Alice's credential can compute Alice's proof.
The application **MUST** either:

1. Use `uor-dag-cbor-ed25519-2025` with distinct signing keys per
   issuer.
2. Layer an out-of-band authentication channel (mutual TLS, OIDC
   tokens) and bind the authenticated issuer identity into the
   credential's `credentialSubject` as a field that canonicalizes
   into the proof.

### 10.4 Verifiable data lake

A research or compliance archive stores datasets indexed by CID.
Queries return the CID; consumers fetch the bytes and verify. The
archive itself does not need to endorse any specific dataset —
dataset authorship is attested separately at ingestion time (e.g.
by an adjacent VC that signs the CID).

This cryptosuite is **sufficient** for the archive's integrity
guarantee, paired with whatever external signing mechanism the
application prefers for authorship attestation. The separation of
integrity (CID) from authorship (signature) is exactly what this
cryptosuite's scope lets you do cleanly.

### 10.5 Federated VC network

A federation of issuers (banks, universities, government
agencies) each produce VCs for their constituents. Verifiers must
determine both that a credential is intact AND that a specific
issuer produced it.

This cryptosuite is **insufficient**. Federations **MUST** use
`uor-dag-cbor-ed25519-2025` (or a comparable signature-bearing
cryptosuite) with the DID-resolution step enabled so the verifier
can confirm the issuer's key.

## 11. Acknowledgments

The authors thank the external reviewer whose round-3 bottle-test
of the reference implementation independently characterized this
cryptosuite as a "tamper-evidence cryptosuite, not a signature
cryptosuite" — "the cheapest honest witness you can compute for a
document." That framing is load-bearing: it names both the
cryptosuite's scope and the scenarios it explicitly does not
serve, and it informed §1.1, §1.2, and the decision to ship a
distinct signed variant (`uor-dag-cbor-ed25519-2025`) rather than
extend this one.

The specification's editors welcome feedback through GitHub
issues on the `sem-ipld-service` repository and, upon formal
registration, through the W3C CCG mailing list and the
`w3c/vc-extensions` tracker. The preferred path for registration
is a pull request against `w3c/vc-extensions` referencing the
stable URL at which this document is hosted. Once that PR lands,
this cryptosuite appears alongside the other DataIntegrity
cryptosuites in every verifier's registry and no longer requires
bespoke registration steps per implementation.

## 12. References

### 12.1 Normative

- [Data Integrity 1.0] — W3C Recommendation, 15 May 2025.
  `https://www.w3.org/TR/vc-data-integrity/`
- [VC Data Model 2.0] — W3C Recommendation, 15 May 2025.
  `https://www.w3.org/TR/vc-data-model-2.0/`
- [IPLD DAG-CBOR] — `https://ipld.io/specs/codecs/dag-cbor/spec/`
- [RFC 8949] — Concise Binary Object Representation (CBOR).
- [FIPS 180-4] — Secure Hash Standard (SHS).
- [Content Identifier (CID) v1] — `https://github.com/multiformats/cid`
- [multibase] — `https://github.com/multiformats/multibase`
- [multihash] — `https://github.com/multiformats/multihash`
- [RFC 2119], [RFC 8174], [BCP 14] — Requirement-level keywords.
- [RFC 3339] — Date and Time on the Internet.

### 12.2 Informative

- [Controlled Identifiers v1.0] — W3C Recommendation.
- [Multikey] — W3C Recommendation.
- [RFC 7234] — HTTP Caching (Warning header).

[Data Integrity 1.0]: https://www.w3.org/TR/vc-data-integrity/
[VC Data Model 2.0]: https://www.w3.org/TR/vc-data-model-2.0/
[IPLD DAG-CBOR]: https://ipld.io/specs/codecs/dag-cbor/spec/
[RFC 8949]: https://www.rfc-editor.org/rfc/rfc8949
[FIPS 180-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[Content Identifier (CID) v1]: https://github.com/multiformats/cid
[multibase]: https://github.com/multiformats/multibase
[multihash]: https://github.com/multiformats/multihash
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[BCP 14]: https://www.rfc-editor.org/bcp/bcp14
[RFC 3339]: https://www.rfc-editor.org/rfc/rfc3339
[Controlled Identifiers v1.0]: https://www.w3.org/TR/cid-1.0/
[Multikey]: https://w3c.github.io/cid/
[RFC 7234]: https://www.rfc-editor.org/rfc/rfc7234
[ref-vectors]: https://github.com/uor-foundation/sem-ipld-service/blob/main/uor-vc-crypto/tests/test_vectors.rs
