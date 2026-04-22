#!/bin/sh
# Boot order inside the container:
#   1. Resolve the listen address (honor $PORT if the platform sets it).
#   2. Initialize Kubo at IPFS_PATH if this is a fresh volume.
#   3. Launch the Kubo daemon in the background.
#   4. Wait for its HTTP RPC to respond.
#   5. Exec the service (replaces shell → signals flow via tini).

set -eu

: "${IPFS_PATH:=/data/ipfs}"
: "${SEM_IPLD_IPFS_API_URL:=http://127.0.0.1:5001}"

# 1. Listen address. Precedence: $PORT (Railway / Render / Heroku
#    convention) wins whenever present; otherwise SEM_IPLD_BIND if set
#    by the operator; otherwise the 0.0.0.0:8787 default from the
#    Dockerfile ENV. This order ensures the image is usable as both
#    a self-hosted docker-run target and a PaaS container.
if [ -n "${PORT:-}" ]; then
    export SEM_IPLD_BIND="0.0.0.0:${PORT}"
fi
: "${SEM_IPLD_BIND:=0.0.0.0:8787}"
export SEM_IPLD_BIND
echo "start: binding on $SEM_IPLD_BIND"

# 2. First-boot init.
if [ ! -f "$IPFS_PATH/config" ]; then
    echo "start: initialising Kubo at $IPFS_PATH (profile=server)"
    mkdir -p "$IPFS_PATH"
    ipfs init --profile=server >/dev/null
fi

# 3. Kubo daemon in the background.
echo "start: launching Kubo daemon"
ipfs daemon --routing=dhtclient >/var/log/ipfs.log 2>&1 &
KUBO_PID=$!

# 4. Wait for RPC (up to 60s) before starting the service.
echo -n "start: waiting for Kubo RPC "
for _ in $(seq 1 60); do
    if curl -sSf -X POST "$SEM_IPLD_IPFS_API_URL/api/v0/version" >/dev/null 2>&1; then
        echo " OK"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -sSf -X POST "$SEM_IPLD_IPFS_API_URL/api/v0/version" >/dev/null 2>&1; then
    echo "start: Kubo RPC never came up; exiting"
    kill "$KUBO_PID" 2>/dev/null || true
    exit 1
fi

# 5. Hand control to the service. `exec` makes it PID 1 under tini, so
#    SIGTERM from the platform / `docker stop` propagates cleanly and
#    the service's fail-fast `/v1/health`-ping gate runs against the
#    now-ready Kubo.
echo "start: launching sem-ipld-service"
exec sem-ipld-service
