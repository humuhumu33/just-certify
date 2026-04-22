# Deploy

A public HTTPS endpoint in under ten minutes, via [Railway](https://railway.com).
No CLI required — GitHub integration does everything.

The `Dockerfile` bundles the service binary with a Kubo sidecar.
It honors `$PORT` (Railway's convention) and falls back to
`SEM_IPLD_BIND` / `8787` for self-hosted Docker runs.

## First-time deploy

1. Push this repository to a GitHub repo you control.
2. Open [railway.com](https://railway.com), **New Project →
   Deploy from GitHub repo**, pick the repo.
3. Railway reads `railway.json`, builds the Dockerfile, and starts
   deploying. First build takes ~5 minutes (Rust cold-compile);
   subsequent builds are ~90 seconds.
4. **Settings → Networking → Generate Domain**. You now have a
   public URL like `https://<your-app>.up.railway.app`.

## Attach a persistent volume (required)

Without this, every redeploy wipes Kubo's blockstore and the
`Cache-Control: immutable` contract breaks across restarts.

1. **Settings → Volumes → Add Volume**.
2. Mount path: `/data`.
3. Size: start with 5 GB. Expand later without data loss.
4. Click **Redeploy** so the running container picks up the mount.

## Canonical URL in responses

By default the service builds `urls.data` / `urls.cert` / `urls.vc`
from the incoming request's `Host` header. Behind Railway's proxy
this is usually correct but can land as the internal hostname in
edge cases. Pin it explicitly:

1. **Settings → Variables**, set `PUBLIC_BASE_URL` to your public
   URL (no trailing slash), e.g.
   `https://just-certify.up.railway.app`.
2. Redeploy.

## Post-deploy smoke

```bash
export API=https://<your-app>.up.railway.app

curl -sS $API/v1/health | jq
# {"status":"ok","store":"kubo 0.30.0","signing":{"enabled":false|true}}

RESP=$(curl -sS -X POST $API/v1/certify \
    -H 'Content-Type: application/json' \
    -d '{"hello":"railway"}')
echo "$RESP" | jq .

DATA_CID=$(echo "$RESP" | jq -r .data_cid)
curl -sSI $API/v1/blocks/$DATA_CID | grep -iE 'HTTP|cache-control|content-type'
# Expect: 200, application/vnd.ipld.raw, Cache-Control immutable

CERT_CID=$(echo "$RESP" | jq -r .certificate_cid)
curl -sSH 'Accept: application/vc+ld+json' \
    "$API/v1/blocks/$CERT_CID?as=vc" | jq .proof
```

All four commands pass → deploy is live.

## Enable the signed cryptosuite (optional)

Skip this if the unsigned `uor-dag-cbor-2025` is sufficient.

```bash
# Locally:
cargo run --release -p uor-vc-crypto --bin gen-issuer-key
# Copy the `private_key_b64` and `public_key_multibase` values.
```

1. Paste `public_key_multibase` into
   `crates/sem-ipld-service/docs/did/did.json` replacing the placeholder,
   commit, and push.
2. **Settings → Variables**, set `SEM_IPLD_ISSUER_KEY_B64` to the
   private key. Railway treats it as a secret.
3. Redeploy.

## Host the `did:web` document (signed mode only)

When signing is enabled, external VC verifiers will try to resolve
`did:web:uor.foundation` → `https://uor.foundation/.well-known/did.json`.
Until that document is reachable, verifiers can check **integrity**
(CID match) but not **authenticity** (signature validity).

Two easy paths:

- **GitHub Pages.** Push a `gh-pages` branch containing
  `.well-known/did.json`, enable Pages, map a DNS A/CNAME for
  `uor.foundation` → `<user>.github.io`. Live within ~5 minutes of
  DNS propagation.
- **Same service.** Add a route in `sem-ipld-service` serving the
  committed `crates/sem-ipld-service/docs/did/did.json` at
  `/.well-known/did.json` with
  `Content-Type: application/did+ld+json`. Point `uor.foundation`
  DNS at the Railway public hostname. One commit + one redeploy.

Unsigned mode (the default) doesn't need this at all.

## Self-hosted Docker (alternative to Railway)

The same image covers any host with Docker:

```bash
docker build -t just-certify .
docker volume create just-certify-data
docker run -d --name just-certify \
    -p 8787:8787 \
    -v just-certify-data:/data \
    just-certify

curl http://localhost:8787/v1/health
```

For production self-hosting, add an HTTPS-terminating reverse proxy
(Caddy or Traefik) in front; Railway gives you this for free.

## Prerequisites

- A GitHub repo with this code.
- A Railway account. The $5/month starter tier covers small
  workloads; free trial available on new accounts.
- Optional: a domain you control, if you want a custom URL instead
  of `*.up.railway.app`.

The Dockerfile clones
`https://github.com/uor-foundation/UOR-Framework` during the build
to resolve the `uor-foundation` path dependency; Railway's build
host has outbound internet by default. That repo must be public
(or you must fork it and edit `Dockerfile` accordingly).

## Common gotchas

- **First deploy fails the healthcheck.** Kubo takes ~15 seconds to
  init on a fresh volume; the 60-second `healthcheckTimeout` in
  `railway.json` absorbs this. If it still fails, check the build
  logs — most likely cause is the UOR-Framework clone failed (see
  below).
- **Build fails with "failed to read manifest at
  `/UOR-Framework/foundation/Cargo.toml`".** The public
  `uor-foundation/UOR-Framework` repo wasn't reachable at build
  time — either a network blip (retry the deploy) or the upstream
  moved. Update the Dockerfile `ARG UOR_FOUNDATION_REF` or the git
  URL to match your fork.
- **`urls.*` fields in responses show the internal hostname.** Set
  `PUBLIC_BASE_URL` as documented above.
- **Build cold-start ≥ 5 minutes.** Rust workspace has ~600
  transitive crates. Railway caches layers across deploys; first
  build is slow, subsequent ones are ~90 seconds.

## Observability

Recommended for anything user-facing:

1. **Railway healthcheck** — already configured (`/v1/health`).
2. **External uptime pinger** — UptimeRobot or BetterStack free
   tiers give 1-minute detection from multiple regions.
3. **End-to-end canary** — a GitHub Actions workflow that does a
   full POST → GET round-trip every 10 minutes. Catches regressions
   health checks miss (CID mismatch, projection errors, expired
   TLS).

---

That's it. Push to GitHub, click deploy, attach volume, curl the
endpoint. The API is live.
