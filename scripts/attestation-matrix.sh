#!/usr/bin/env bash
# Evaluate every committed fixture and print a single verdict matrix.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${FLEETCTL:-target/debug/fleetctl}"
if [[ ! -x "$BIN" ]]; then
  cargo build -q -p fleetctl
fi

POLICY="${POLICY:-policy/boot-integrity.yaml}"
CA_BUNDLE="${CA_BUNDLE:-fixtures/ca.pem}"

echo "# FleetProvision attestation matrix"
echo
echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
echo
echo "Command: fleetctl attest check --fixture <fixture> --policy $POLICY --ca-bundle $CA_BUNDLE"
echo
printf '%-26s %-6s %s\n' "fixture" "result" "violations"
printf '%s\n' "------------------------------------------------------------------------------"
for fixture in fixtures/*.json; do
  # The CLI exits 2 for a failed policy; capture the verdict row either way.
  row=$("$BIN" attest check --fixture "$fixture" --policy "$POLICY" --ca-bundle "$CA_BUNDLE" 2>&1 | tail -n 1 || true)
  printf '%s\n' "$row"
done
