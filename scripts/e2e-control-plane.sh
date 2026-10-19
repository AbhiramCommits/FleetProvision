#!/usr/bin/env bash
# End-to-end control-plane demonstration: enroll two nodes, revoke one, and
# prove the revoked certificate is refused at the TLS handshake.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools:$PATH"

OUT="${E2E_OUT:-out/e2e-control-plane}"
STATE="$OUT/state"
BIN="$PWD/target/debug"
mkdir -p "$OUT" results
rm -rf "$STATE" "$OUT/agents" "$OUT/token-"*
mkdir -p "$STATE" "$OUT/agents"

pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
MTLS_PORT=$(pick_port)
ENROLL_PORT=$(pick_port)
OPERATOR_PORT=$(pick_port)

cargo build -q -p fleetd -p fleetctl

"$BIN/fleetctl" --state-dir "$STATE" ca init >"$OUT/ca-init.txt"
"$BIN/fleetctl" --state-dir "$STATE" ca issue --node-id operator-admin >"$OUT/operator-issue.txt"

RUST_LOG="fleetd=info" "$BIN/fleetd" \
  --state-dir "$STATE" \
  --listen "127.0.0.1:$MTLS_PORT" \
  --enroll-listen "127.0.0.1:$ENROLL_PORT" \
  --operator-listen "127.0.0.1:$OPERATOR_PORT" \
  >"$OUT/fleetd.log" 2>&1 &
FLEETD_PID=$!
trap 'kill "$FLEETD_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  if curl -sk "https://127.0.0.1:$ENROLL_PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

FLEETCTL=("$BIN/fleetctl" --state-dir "$STATE" --server "https://127.0.0.1:$OPERATOR_PORT")

"${FLEETCTL[@]}" token create --node-id n1 --site dc1 --out "$OUT/token-n1" >/dev/null 2>&1
"${FLEETCTL[@]}" token create --node-id n2 --site dc1 --out "$OUT/token-n2" >/dev/null 2>&1

for node in n1 n2; do
  "$BIN/fleet-agent" enroll \
    --enroll-url "https://127.0.0.1:$ENROLL_PORT" \
    --node-id "$node" \
    --site dc1 \
    --token "$(cat "$OUT/token-$node")" \
    --state-dir "$OUT/agents/$node" \
    --ca-bundle "$STATE/trust-bundle.pem" >"$OUT/enroll-$node.txt" 2>&1
done

echo "== enrolled nodes ==" | tee "$OUT/summary.txt"
"${FLEETCTL[@]}" node list | tee -a "$OUT/summary.txt"

echo "== revoking n2 ==" | tee -a "$OUT/summary.txt"
"${FLEETCTL[@]}" node revoke n2 | tee -a "$OUT/summary.txt" >/dev/null

set +e
REVOKED_OUTPUT=$(curl -sS --cert "$OUT/agents/n2/node/node.crt.pem" \
  --key "$OUT/agents/n2/node/node.key.pem" \
  --cacert "$STATE/root-cert.pem" \
  "https://127.0.0.1:$MTLS_PORT/v1/whoami" 2>&1)
REVOKED_STATUS=$?
set -e
if [[ $REVOKED_STATUS -eq 0 ]]; then
  echo "ERROR: revoked certificate was accepted" | tee -a "$OUT/summary.txt"
  exit 1
fi

echo "== revoked node handshake (exit $REVOKED_STATUS) ==" | tee -a "$OUT/summary.txt"
echo "$REVOKED_OUTPUT" | tee -a "$OUT/summary.txt"

sleep 0.2
kill "$FLEETD_PID" 2>/dev/null || true
wait "$FLEETD_PID" 2>/dev/null || true
trap - EXIT

{
  echo "# FleetProvision control-plane e2e"
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
  echo
  cat "$OUT/summary.txt"
  echo
  echo "## fleetd log (real lines)"
  echo '```'
  cat "$OUT/fleetd.log"
  echo '```'
} > results/e2e.txt

echo
echo "captured results/e2e.txt"
