# Deploy to Fly.io

Ten minutes from `git pull` to a public HTTPS endpoint.

## Prerequisites

```bash
# 1. Fly CLI.
brew install flyctl      # macOS
# or: curl -L https://fly.io/install.sh | sh

# 2. Fly account.
flyctl auth signup       # if new
flyctl auth login        # if returning
```

You'll need a payment card on file. Fly's free allowance covers this
workload; expect **$0–5/month** depending on traffic.

## First-time deploy

```bash
# 1. Clone the repo.
git clone https://github.com/humuhumu33/just-certify.git
cd just-certify

# 2. Launch. This reads the committed fly.toml and registers the app
#    with Fly; it does NOT yet deploy code.
flyctl launch --copy-config --no-deploy
# Accept the defaults when prompted; the fly.toml has everything needed.

# 3. Create the persistent volume for Kubo's blockstore. 5 GB is
#    enough for millions of small blocks; bump to 20+ GB if you plan
#    to store PDFs / model weights.
flyctl volumes create ipfs_data --size 5 --region ord

# 4. Build & ship the Docker image.
flyctl deploy

# 5. Grab your public URL.
flyctl status
# Hostname shows as https://just-certify.fly.dev (or your chosen app name).
```

Wait ~30 seconds after `flyctl deploy` completes for the Kubo daemon
to finish its first-time init. Then:

```bash
export API=$(flyctl info --json | jq -r '.Hostname' | sed 's|^|https://|')
curl -sS $API/v1/health | jq .
# Expect: {"status":"ok","store":"kubo 0.30.0","signing":{"enabled":false}}
```

## Post-deploy smoke

All five should pass:

```bash
# 1. Health.
curl -sS $API/v1/health | jq .

# 2. OpenAPI spec reachable.
curl -sSI $API/v1/openapi.yaml | head -1

# 3. Certify a payload.
RESP=$(curl -sS -X POST $API/v1/certify \
    -H 'Content-Type: application/json' \
    -d '{"hello":"production"}')
echo "$RESP" | jq .

# 4. Fetch the data block (IPIP-402 raw).
DATA_CID=$(echo "$RESP" | jq -r .data_cid)
curl -sSI $API/v1/blocks/$DATA_CID | grep -i -E 'HTTP|cache-control|content-type'
# Expect: 200, application/vnd.ipld.raw, immutable.

# 5. VC projection (unsigned cryptosuite).
curl -sSH 'Accept: application/vc+ld+json' \
    $API/v1/blocks/$(echo "$RESP" | jq -r .certificate_cid)?as=vc | jq .proof
```

If all five pass, the API is live.

## Enable the signed cryptosuite (optional)

Skip this if you're running unsigned mode. Flip at any time later.

```bash
# 1. Generate a keypair locally.
cargo run --release -p uor-vc-crypto --bin gen-issuer-key
#  private_key_b64:      <X>
#  public_key_multibase: <Y>

# 2. Inject the private seed as a Fly secret (never commit this).
flyctl secrets set SEM_IPLD_ISSUER_KEY_B64='<X>'

# 3. Update the DID document with <Y>.
vim sem-ipld-service/docs/did/did.json       # paste <Y> into publicKeyMultibase
git commit -am "Rotate issuer key"
git push

# 4. Redeploy.
flyctl deploy

# 5. Verify.
curl -sS $API/v1/health | jq .signing
# { "enabled": true, "algorithm": "ed25519",
#   "public_key_multibase": "<Y>",
#   "verification_method": "did:web:uor.foundation#key-1" }
```

## Host the DID document

Required only if external verifiers need to resolve
`did:web:uor.foundation`. Two paths:

**GitHub Pages (easy).** Push a `gh-pages` branch with
`.well-known/did.json` at its root. Map a DNS A/CNAME record for
`uor.foundation` → `humuhumu33.github.io` and enable Pages. The file
becomes reachable at `https://uor.foundation/.well-known/did.json`
within ~5 minutes.

**Same Fly app (20 LOC).** Add an Axum route serving the committed
`sem-ipld-service/docs/did/did.json` at `/.well-known/did.json` with
`Content-Type: application/did+ld+json`. Point `uor.foundation` DNS
at the Fly app. The DID doc ships with every deploy.

Either way: until the DID doc is reachable, verifiers can still check
**integrity** (CID match) but not **authenticity** (signature
validity). Unsigned mode doesn't need it at all.

## Day-2 operations

```bash
# Tail logs.
flyctl logs

# SSH into the running machine (rarely needed).
flyctl ssh console

# Scale to multiple regions (for lower p99 globally).
flyctl scale count 2 --region ord,fra

# Rolling restart (picks up new secrets without a deploy).
flyctl machine restart

# Destroy if you need to start over.
flyctl apps destroy just-certify
```

## Common gotchas

- **First deploy fails with "store ping FAILED"** — Kubo takes ~15
  seconds to initialize on a fresh volume. The fly.toml
  `grace_period = "30s"` absorbs this; if your deploy still fails,
  increase it to `60s` and redeploy.
- **`curl -I` returns nothing** — `-I` sends HEAD; the service only
  implements GET/POST. Use `curl -si` for headers with a POST body.
- **`urls.data` / `urls.cert` in responses point at the wrong host** —
  set `PUBLIC_BASE_URL` in fly.toml to your canonical origin
  (e.g. `https://just-certify.fly.dev`) and redeploy.
- **Build cold-starts take 5+ minutes** — the Rust build has ~600
  transitive crates. Fly's remote builder caches across deploys; the
  first build is slow, subsequent ones are ~90 seconds.

## Observability

Three signals I recommend wiring before you tell anyone the API is
live:

1. **Fly's built-in health check** — configured above. Polls every
   15s; a failure triggers auto-restart.
2. **External uptime pinger** — [UptimeRobot](https://uptimerobot.com)
   or [BetterStack](https://betterstack.com) free tiers give 1-minute
   detection from multiple regions.
3. **End-to-end canary** — a GitHub Actions workflow (free for public
   repos) that does a full POST → GET round-trip every 10 minutes and
   opens an issue when it fails. Catches things health checks miss
   (CID-mismatch, projection errors, expired TLS, etc.).

That's it. `flyctl deploy` and you're live.
