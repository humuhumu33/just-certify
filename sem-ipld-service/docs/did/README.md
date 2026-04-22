# `did:web:uor.foundation` — issuer DID

Every VC credential this service emits has `issuer: did:web:uor.foundation`.
To make those credentials verifiable by external W3C stacks, the
`did.json` file in this directory must be served at

    https://uor.foundation/.well-known/did.json

with the following headers:

    Content-Type: application/did+ld+json
    Cache-Control: public, max-age=86400

## What's in v0.4.0

v0.4.0 ships a real Ed25519 public key in the `publicKeyMultibase`
field (prefix `z6Mk`, per the W3C Multikey spec for Ed25519).
**The example key committed to git is a demo key** — replace it
with your operator-controlled key before deploying to production.

The `assertionMethod` and `authentication` arrays both reference
`did:web:uor.foundation#key-1`, so the key is usable both for
asserting VC credentials and for future DID authentication flows.

## Operator checklist (one-time, ordered)

1. **Generate a key.**

   ```bash
   cargo run --release -p uor-vc-crypto --bin gen-issuer-key
   ```

   The binary prints four lines:

   - `private_key_b64:      …`  — goes into the service's
     `SEM_IPLD_ISSUER_KEY_B64` environment variable.
   - `public_key_multibase: z6Mk…` — goes into `did.json`.
   - `verification_method:  did:web:uor.foundation#key-1` — already
     hard-coded in the service; reminder only.
   - `self_check: ok` — if this says anything else, stop and file
     an issue.

2. **Update this directory's `did.json`.** Replace the
   `publicKeyMultibase` value with the `z6Mk…` output from step 1.
   Commit.

3. **Set the environment variable on the production host.**
   Kubernetes:

   ```yaml
   env:
     - name: SEM_IPLD_ISSUER_KEY_B64
       valueFrom:
         secretKeyRef: { name: uor-issuer-key, key: seed-b64 }
   ```

   systemd:

   ```ini
   [Service]
   EnvironmentFile=/etc/sem-ipld-service/issuer.env
   # issuer.env contains: SEM_IPLD_ISSUER_KEY_B64=…
   ```

   **Never commit the private key.** It must be injected at runtime
   from a secret manager (Kubernetes Secret, AWS Secrets Manager,
   Vault, 1Password CLI, etc.).

4. **Publish `did.json`.** Serve the committed file at
   `https://uor.foundation/.well-known/did.json`. Any static host
   works; the file is ~400 bytes and changes rarely.

5. **Restart the service.** On startup, it reads
   `SEM_IPLD_ISSUER_KEY_B64`, parses it, and logs
   `signing enabled (uor-dag-cbor-ed25519-2025)`. The
   `/v1/health` endpoint now returns
   `signing.enabled: true` with the public key's multibase form.

6. **Confirm end-to-end.** A VC fetched from
   `GET /v1/blocks/<cert_cid>?as=vc` has
   `proof.cryptosuite: uor-dag-cbor-ed25519-2025`. Pipe it through
   `verify_signed_smoke_test`:

   ```bash
   cargo run --release -p uor-vc-crypto --bin verify_signed_smoke_test -- "$VC"
   # VC verified (signed): Ok
   ```

## Key rotation

Not supported in v0.4.0. Rotation is post-v1.0 scope — when it
arrives it will publish multiple `verificationMethod` entries in
the DID document and introduce `#key-N` identifiers.

## Unsigned mode — what happens if you skip this

If `SEM_IPLD_ISSUER_KEY_B64` is unset, the service runs in unsigned
mode: VCs emit `cryptosuite: uor-dag-cbor-2025` and the
`proofValue` is a CID (not an Ed25519 signature). The DID document
isn't consulted at all. This is the v0.3.0 behaviour, valid for
single-writer / trusted-cluster deployments. The checklist above
only applies to federated / multi-party scenarios where signature
authenticity matters.
