#!/usr/bin/env python3
"""
just-certify API Battle Test
=============================
Run against any deployment of the sem-ipld-service to verify correctness,
universality, idempotency, and error handling across every supported
content type and payload shape.

Usage:
    python battle_test.py                                          # default: production
    python battle_test.py https://just-certify-production.up.railway.app
    python battle_test.py http://localhost:8787                    # local

Requirements: Python 3.9+, requests library
    pip install requests
"""

import sys
import json
import hashlib
import base64
import struct
import time
import requests

BASE = (sys.argv[1] if len(sys.argv) > 1
        else "https://just-certify-production.up.railway.app").rstrip("/")

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"

passed = failed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  {PASS} {msg}")


def fail(msg, detail=""):
    global failed
    failed += 1
    print(f"  {FAIL} {msg}")
    if detail:
        print(f"      >> {detail}")


def section(title):
    print(f"\n{'-'*60}")
    print(f"  {title}")
    print(f"{'-'*60}")


# ─── helpers ─────────────────────────────────────────────────────────────────

def certify(payload, content_type="application/json"):
    if content_type == "application/json":
        r = requests.post(f"{BASE}/v1/certify",
                          json=payload, timeout=30)
    else:
        r = requests.post(f"{BASE}/v1/certify",
                          data=payload,
                          headers={"Content-Type": content_type},
                          timeout=30)
    return r


def assert_certify_shape(body, label):
    """Assert every required field is present and well-formed (v0.5.0 JSON-LD shape)."""
    required = ["@context", "@type", "uor_address", "@id", "certificate",
                "integrity", "digestMultibase", "foundation_version", "gateway"]
    for field in required:
        if field not in body:
            fail(f"{label}: missing field '{field}'")
            return False

    # @context must be the UOR ontology IRI (canonical: "https://uor.foundation/")
    if not body["@context"].startswith("https://uor.foundation"):
        fail(f"{label}: @context not the UOR ontology IRI", body["@context"])
        return False
    # @type grounded in UOR-Framework state namespace
    if body["@type"] != "https://uor.foundation/state/GroundedContext":
        fail(f"{label}: @type unexpected", body["@type"])
        return False
    # uor_address must be multibase base58btc (z prefix)
    if not body["uor_address"].startswith("z"):
        fail(f"{label}: uor_address not multibase base58btc", body["uor_address"])
        return False
    # @id must be ipfs://<data_cid>
    if not body["@id"].startswith("ipfs://baf"):
        fail(f"{label}: @id not an ipfs:// URI", body["@id"])
        return False
    # certificate must be ipfs://<cert_cid>
    if not body["certificate"].startswith("ipfs://bafyrei"):
        fail(f"{label}: certificate not an ipfs:// URI", body["certificate"])
        return False
    if not body["integrity"].startswith("sha256-"):
        fail(f"{label}: integrity not SRI sha256", body["integrity"])
        return False
    if not body["digestMultibase"].startswith("u"):
        fail(f"{label}: digestMultibase not base64url multibase", body["digestMultibase"])
        return False

    gateway = body.get("gateway", {})
    for key in ["data", "cert", "jsonld", "vc"]:
        if not gateway.get(key, "").startswith(BASE):
            fail(f"{label}: gateway.{key} missing or wrong base", gateway.get(key))
            return False

    ok(f"{label}: response shape valid")
    return True


def assert_vc(vc_body, label):
    """Assert W3C VC 2.0 shape."""
    required = ["@context", "type", "id", "issuer", "validFrom",
                "credentialSubject", "proof"]
    for field in required:
        if field not in vc_body:
            fail(f"{label} VC: missing '{field}'")
            return False
    proof = vc_body["proof"]
    if proof.get("type") != "DataIntegrityProof":
        fail(f"{label} VC: wrong proof type", proof.get("type"))
        return False
    if proof.get("cryptosuite") not in (
            "uor-dag-cbor-2025", "uor-dag-cbor-ed25519-2025"):
        fail(f"{label} VC: unrecognised cryptosuite", proof.get("cryptosuite"))
        return False
    ok(f"{label}: W3C VC 2.0 shape valid")
    return True


# ─── 1. Infrastructure ───────────────────────────────────────────────────────

section("1 · Infrastructure")

r = requests.get(f"{BASE}/v1/health", timeout=15)
if r.status_code == 200:
    h = r.json()
    if h.get("status") == "ok":
        ok(f"Health: status=ok  store={h.get('store')}  "
           f"signing={h['signing']['enabled']}")
    else:
        fail("Health: status != ok", h)
else:
    fail(f"Health: HTTP {r.status_code}")

r = requests.get(f"{BASE}/v1/openapi.yaml", timeout=15)
if r.status_code == 200 and r.text.startswith("openapi: 3.1.0"):
    ok("OpenAPI spec served at /v1/openapi.yaml (3.1.0)")
else:
    fail("OpenAPI spec not served correctly", r.status_code)

# AI agent discovery
r = requests.get(f"{BASE}/.well-known/ai-plugin.json", timeout=15)
if r.status_code == 200:
    m = r.json()
    if all(k in m for k in ["schema_version", "name_for_model",
                             "description_for_model", "api"]):
        ok(f"AI plugin manifest: name_for_model={m['name_for_model']}")
    else:
        fail("AI plugin manifest: missing required fields", list(m.keys()))
else:
    fail(f"AI plugin manifest: HTTP {r.status_code}")

r = requests.get(f"{BASE}/v1/openai-tools", timeout=15)
if r.status_code == 200:
    tools = r.json()
    names = [t["function"]["name"] for t in tools
             if t.get("type") == "function"]
    if "certify_object" in names:
        ok(f"OpenAI tools: {len(tools)} tool(s) — {names}")
    else:
        fail("OpenAI tools: certify_object not found", names)
else:
    fail(f"OpenAI tools: HTTP {r.status_code}")

# Content-Type on certify response must be application/ld+json (W3C JSON-LD)
r = certify({"content_type_probe": True})
if r.status_code == 201:
    ct = r.headers.get("content-type", "")
    if "application/ld+json" in ct:
        ok("certify response Content-Type: application/ld+json (W3C compliant)")
    else:
        fail("certify response Content-Type not application/ld+json", ct)


# ─── 2. Payload universality ─────────────────────────────────────────────────

section("2 · Payload universality — diverse JSON objects")

PAYLOADS = {
    "empty object":
        {},

    "flat string values":
        {"name": "Ada Lovelace", "role": "mathematician", "era": "1840s"},

    "nested object":
        {"model": {"name": "gpt-x", "version": "1.0",
                   "params": {"layers": 96, "heads": 96, "dim": 12288}}},

    "array of primitives":
        {"tags": ["ai", "ipld", "w3c", "uor"], "scores": [0.99, 0.87, 0.73]},

    "deeply nested":
        {"a": {"b": {"c": {"d": {"e": {"f": "leaf"}}}}}},

    "numeric types":
        {"int": 42, "negative": -7, "zero": 0,
         "large": 9007199254740991},          # 2^53 - 1

    "boolean and null":
        {"active": True, "deleted": False, "metadata": None},

    "unicode and emoji":
        {"greeting": "こんにちは", "flag": "🏴‍☠️", "arabic": "مرحبا"},

    "legal document metadata":
        {"docType": "contract", "parties": ["Alice Corp", "Bob Ltd"],
         "jurisdiction": "EU", "signed": "2026-01-15",
         "clauses": 42, "confidential": True},

    "financial transaction":
        {"txId": "TX-20260422-0001", "from": "acct_A", "to": "acct_B",
         "amount": 1250, "currency": "USD", "timestamp": 1745359200,
         "status": "settled"},

    "scientific observation":
        {"instrument": "ALMA", "target": "NGC 1068",
         "frequency_GHz": 230.538, "integration_s": 3600,
         "flux_Jy": 0.00412, "snr": 18.7},

    "AI model card":
        {"modelId": "uor-embed-v1", "architecture": "transformer",
         "parameters_B": 7, "license": "Apache-2.0",
         "languages": ["en", "zh", "ar"],
         "tasks": ["embedding", "retrieval"],
         "trainedOn": "CommonCrawl-2025"},

    "geospatial feature":
        {"type": "Feature", "geometry": {"type": "Point",
         "coordinates": [103.8198, 1.3521]},
         "properties": {"name": "Singapore", "population": 5900000}},

    "supply chain item":
        {"sku": "SC-789-XL", "origin": "SG", "destination": "DE",
         "weight_kg": 14.2, "carrier": "DHL",
         "checkpoints": ["SIN", "FRA", "BER"]},

    "medical record stub":
        {"patientId": "hash:sha256:abc123", "encounterDate": "2026-04-22",
         "diagnoses": ["J06.9"], "vitals": {"bp": "120/80", "hr": 72}},

    "software bill of materials":
        {"bomFormat": "CycloneDX", "specVersion": "1.4",
         "components": [
             {"name": "axum", "version": "0.7.9", "license": "MIT"},
             {"name": "tokio", "version": "1.52.1", "license": "MIT"},
         ]},

    "identity assertion":
        {"@context": "https://www.w3.org/ns/did/v1",
         "id": "did:example:123456",
         "verificationMethod": [{"id": "#key-1", "type": "Ed25519"}]},
}

cid_registry = {}   # label -> (id_uri, certificate_uri) for idempotency re-check

for label, payload in PAYLOADS.items():
    r = certify(payload)
    if r.status_code != 201:
        fail(f"{label}: HTTP {r.status_code}", r.text[:120])
        continue
    body = r.json()
    if assert_certify_shape(body, label):
        cid_registry[label] = (body["@id"], body["certificate"])


# ─── 3. Opaque / binary payloads ─────────────────────────────────────────────

section("3 · Opaque binary payloads (codec=raw)")

BINARY_PAYLOADS = {
    "PDF magic bytes":
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj",

    "PNG header":
        b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"IHDR" + struct.pack(">II", 64, 64),

    "CBOR-encoded integer":
        bytes([0x18, 0x2a]),   # CBOR for integer 42

    "random binary blob":
        bytes(range(256)),

    "null bytes":
        b"\x00" * 64,

    "UTF-8 text as octet-stream":
        "The quick brown fox jumps over the lazy dog.".encode(),
}

for label, payload in BINARY_PAYLOADS.items():
    r = certify(payload, content_type="application/octet-stream")
    if r.status_code != 201:
        fail(f"{label}: HTTP {r.status_code}", r.text[:120])
        continue
    body = r.json()
    if assert_certify_shape(body, label):
        # Warning header should be present for unrecognised content-type
        # (octet-stream is accepted; no warning needed — just verify shape)
        cid_registry[f"bin:{label}"] = (body["@id"], body["certificate"])


# ─── 4. Idempotency ──────────────────────────────────────────────────────────

section("4 · Idempotency — same payload must yield identical CIDs")

IDEM_SAMPLES = ["flat string values", "financial transaction", "AI model card"]

for label in IDEM_SAMPLES:
    if label not in cid_registry:
        continue
    original_id, original_cert = cid_registry[label]
    r = certify(PAYLOADS[label])
    if r.status_code != 201:
        fail(f"{label}: HTTP {r.status_code} on second call")
        continue
    body = r.json()
    if (body["@id"] == original_id and
            body["certificate"] == original_cert):
        ok(f"{label}: idempotent (same URIs on second call)")
    else:
        fail(f"{label}: URIs differ between calls — not idempotent",
             f"expected {original_id}, got {body['@id']}")


# ─── 5. DAG-CBOR canonicalization ────────────────────────────────────────────

section("5 · DAG-CBOR canonicalization — key order must not affect CID")

r1 = certify({"a": 1, "b": 2, "c": 3})
r2 = certify({"c": 3, "a": 1, "b": 2})
r3 = certify({"b": 2, "c": 3, "a": 1})

if all(r.status_code == 201 for r in [r1, r2, r3]):
    ids = [r.json()["@id"] for r in [r1, r2, r3]]
    if len(set(ids)) == 1:
        ok(f"All 3 key orderings -> identical @id: {ids[0]}")
    else:
        fail("Key orderings produced different @ids -- canonicalization broken", ids)
else:
    fail("One or more canonicalization requests failed")

# Nested key order
r1 = certify({"x": {"p": 1, "q": 2}, "y": "val"})
r2 = certify({"y": "val", "x": {"q": 2, "p": 1}})
if r1.status_code == 201 and r2.status_code == 201:
    if r1.json()["@id"] == r2.json()["@id"]:
        ok("Nested key reordering -> identical @id")
    else:
        fail("Nested key reordering produced different @ids")


# ─── 6. Block gateway & projections ──────────────────────────────────────────

section("6 · Block gateway — raw, JSON-LD, and VC projections")

# Use a freshly certified payload for projection tests
r = certify({"battle_test": True, "ts": int(time.time())})
if r.status_code == 201:
    body = r.json()
    # Extract bare CIDs from ipfs:// URIs
    data_cid = body["@id"].removeprefix("ipfs://")
    cert_cid = body["certificate"].removeprefix("ipfs://")

    # Raw data block
    r_raw = requests.get(f"{BASE}/v1/blocks/{data_cid}", timeout=15)
    if r_raw.status_code == 200:
        ok(f"GET /v1/blocks/{{data_cid}} -> 200 ({len(r_raw.content)} bytes)")
    else:
        fail(f"Raw data block: HTTP {r_raw.status_code}")

    # Raw cert block
    r_cert = requests.get(f"{BASE}/v1/blocks/{cert_cid}", timeout=15)
    if r_cert.status_code == 200:
        ok(f"GET /v1/blocks/{{cert_cid}} -> 200 ({len(r_cert.content)} bytes)")
    else:
        fail(f"Raw cert block: HTTP {r_cert.status_code}")

    # JSON-LD projection
    r_jsonld = requests.get(f"{BASE}/v1/blocks/{cert_cid}?as=jsonld", timeout=15)
    if r_jsonld.status_code == 200:
        jld = r_jsonld.json()
        if "@context" in jld and "@type" in jld:
            ok("JSON-LD projection: @context and @type present")
        else:
            fail("JSON-LD projection: missing @context or @type", list(jld.keys()))
    else:
        fail(f"JSON-LD projection: HTTP {r_jsonld.status_code}")

    # VC 2.0 projection
    r_vc = requests.get(f"{BASE}/v1/blocks/{cert_cid}?as=vc", timeout=15)
    if r_vc.status_code == 200:
        assert_vc(r_vc.json(), "VC projection")
    else:
        fail(f"VC projection: HTTP {r_vc.status_code}")

    # 406 on data block for projections
    r_406 = requests.get(f"{BASE}/v1/blocks/{data_cid}?as=vc", timeout=15)
    if r_406.status_code == 406:
        ok("GET data_cid?as=vc -> 406 (not acceptable, correct)")
    else:
        fail(f"Expected 406 for VC on data block, got {r_406.status_code}")


# ─── 7. Error handling ───────────────────────────────────────────────────────

section("7 · Error handling")

# Malformed JSON
r = requests.post(f"{BASE}/v1/certify",
                  data=b"{not valid json",
                  headers={"Content-Type": "application/json"},
                  timeout=15)
if r.status_code == 400:
    body = r.json()
    if "error" in body:
        ok(f"Malformed JSON -> 400 with error tag: '{body['error']}'")
    else:
        fail("Malformed JSON -> 400 but no 'error' field in body")
else:
    fail(f"Malformed JSON: expected 400, got {r.status_code}")

# Integer out of DAG-CBOR range (> u64::MAX)
r = certify({"n": 99999999999999999999999999})
if r.status_code == 400:
    body = r.json()
    ok(f"Bignum out of range -> 400: '{body.get('error', '?')}'")
else:
    fail(f"Bignum: expected 400, got {r.status_code}")

# Non-finite float
r = requests.post(f"{BASE}/v1/certify",
                  data=b'{"x": Infinity}',
                  headers={"Content-Type": "application/json"},
                  timeout=15)
if r.status_code == 400:
    ok("Non-finite float -> 400")
else:
    fail(f"Non-finite float: expected 400, got {r.status_code}")

# 404 for unknown CID
fake_cid = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
r = requests.get(f"{BASE}/v1/blocks/{fake_cid}", timeout=15)
if r.status_code == 404:
    ok("Unknown CID -> 404")
elif r.status_code == 400:
    ok("Unknown CID -> 400 (malformed CID, also acceptable)")
else:
    fail(f"Unknown CID: expected 404/400, got {r.status_code}")

# 400 for malformed CID
r = requests.get(f"{BASE}/v1/blocks/not-a-cid", timeout=15)
if r.status_code == 400:
    ok("Malformed CID path -> 400")
else:
    fail(f"Malformed CID: expected 400, got {r.status_code}")


# ─── 8. SRI integrity cross-check ────────────────────────────────────────────

section("8 · SRI integrity cross-check")

payload = {"integrity_test": "verify me", "value": 42}
r = certify(payload)
if r.status_code == 201:
    body = r.json()
    # Fetch the raw block bytes
    raw = requests.get(body["gateway"]["data"], timeout=15)
    if raw.status_code == 200:
        digest = hashlib.sha256(raw.content).digest()
        expected_sri = "sha256-" + base64.b64encode(digest).decode()
        if body["integrity"] == expected_sri:
            ok(f"SRI integrity matches SHA-256 of raw block bytes")
        else:
            fail("SRI mismatch",
                 f"expected {expected_sri}, got {body['integrity']}")
    else:
        fail(f"Could not fetch raw block for SRI check: {raw.status_code}")


# ─── 9. Concurrent load ──────────────────────────────────────────────────────

section("9 · Concurrent load — 10 parallel certify calls")

import concurrent.futures

def fire(i):
    return certify({"concurrent": True, "id": i, "ts": time.time()})

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futures = [ex.submit(fire, i) for i in range(10)]
    results = [f.result() for f in concurrent.futures.as_completed(futures)]

successes = sum(1 for r in results if r.status_code == 201)
if successes == 10:
    ok("10/10 concurrent requests succeeded")
else:
    fail(f"Only {successes}/10 concurrent requests succeeded")


# ─── Summary ─────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
total = passed + failed
pct = int(100 * passed / total) if total else 0
status = "\033[32mALL PASS\033[0m" if failed == 0 else f"\033[31m{failed} FAILED\033[0m"
print(f"  {status}   {passed}/{total} checks passed ({pct}%)")
print(f"  Tested against: {BASE}")
print(f"{'='*60}\n")

sys.exit(0 if failed == 0 else 1)
