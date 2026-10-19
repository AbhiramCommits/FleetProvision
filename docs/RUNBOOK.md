# FleetProvision runbook

All commands assume the repository root and `STATE=./state`. Substitute your
environment. Never copy private keys off a node or the CA host.

## Daily checks

```bash
export STATE=./state
./target/debug/fleetctl --state-dir "$STATE" ca show | head -20
./target/debug/fleetctl --state-dir "$STATE" audit verify
./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 \
  login --idp http://127.0.0.1:8080 --group fleet-operator
./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 node list
curl -s https://127.0.0.1:8444/healthz
```

Check `nextUpdate` on the CRL:

```bash
openssl crl -in "$STATE/crl.pem" -noout -lastupdate -nextupdate
```

## Rotate the intermediate

Rotating keeps the old intermediate in the trust bundle until its expiry; leaves
already issued remain valid.

1. Back up `state/` (see below).
2. Rotate:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" ca rotate
   ./target/debug/fleetctl --state-dir "$STATE" ca show | head -20
   ```

3. Confirm the bundle now contains root + old + new intermediate:

   ```bash
   grep -c 'BEGIN CERTIFICATE' "$STATE/trust-bundle.pem"
   ```

4. Restart `fleetd` so the in-memory verifier reloads the bundle. New leaves use
   the new intermediate. Old leaves keep verifying.
5. Update the trust bundle on nodes (`/etc/fleet-agent/trust-bundle.pem`) before
   the old intermediate expires; roll it with Ansible or the image pipeline.
6. Revoke the old intermediate only after every old leaf has expired.

## Revoke a compromised node

1. Revoke through the operator API (preferred; requires `fleet-admin`):

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 \
     node revoke n17
   ```

   Or locally if the control plane is down:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" ca revoke --serial <serial> \
     --reason key_compromise
   ```

   The local path updates the CRL immediately but does not change the node's
   `nodes.json` state; update that record (or revoke through the API when the
   control plane returns) so `node describe` reflects reality.

2. Verify the CRL contains the serial and is fresh:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" ca crl >/dev/null
   ./target/debug/fleetctl --state-dir "$STATE" ca verify --node-id n17   # should fail
   ```

3. Confirm the next mTLS attempt fails:

   ```bash
   curl --cert node.crt.pem --key node.key.pem --cacert "$STATE/root-cert.pem" \
     https://127.0.0.1:8443/v1/whoami
   # LibreSSL/OpenSSL: sslv3 alert certificate revoked
   ```

4. Check the audit chain:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" audit verify
   ```

5. Isolate the switch port (VLAN 666) or power off the host. `Revoked` is
   terminal for that identity.

## Re-image a quarantined node

1. Read the violations:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 \
     node describe n17
   ```

2. Decide whether the cause is policy drift (legitimate firmware update) or
   tampering. For a legitimate update, add the measured PCR value to
   `policy/boot-integrity.yaml` only after reviewing the event log and firmware
   provenance.

3. Re-image from the current golden image. Prefer a **new node identity** for a
   previously revoked node; the old identity cannot re-enroll.
4. Issue a fresh single-use token:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 \
     token create --node-id n17b --site dc1 --out out/n17b.token
   ```

5. Boot the node and confirm enrollment, attestation pass, and VLAN 100:

   ```bash
   ./target/debug/fleetctl --state-dir "$STATE" --server https://127.0.0.1:9443 \
     node describe n17b
   ```

6. If the node was quarantined rather than revoked, remediation plus a fresh
   token moves it `Quarantined → Attested → Enrolled`.

## Roll a new golden image

1. On a Linux/KVM build host:

   ```bash
   cargo build --release -p fleetd --bin fleet-agent
   cd packer/ubuntu && packer init . && packer validate . && packer build .
   cd ../fedora && packer init . && packer validate . && packer build .
   ```

   The build writes `out/*.qcow2`, `out/*-manifest.json`, and a SHA-256 file.

2. Test the image in the simulator or a canary rack first:

   ```bash
   make e2e
   ```

3. Update the AMI in `terraform/envs/dev` (`node_ami`) or the qcow2 path in
   `terraform/envs/onprem` (`image_path`).

4. Roll nodes in batches; after each batch confirm:
   - `node list` shows `enrolled`
   - `violations` is empty
   - 802.1X assigns VLAN 100
   - `audit verify` passes

5. Keep the previous image available for rollback until the fleet is fully
   migrated. A node that fails attestation after an upgrade is quarantined
   automatically; do not disable the policy to force it through.

## Backup and restore

```bash
tar --exclude='*.log' -czf fleet-state-$(date +%Y%m%d).tgz "$STATE"
```

Restore only on a trusted host with the same file modes. After restore:

```bash
./target/debug/fleetctl --state-dir "$STATE" ca verify --node-id <node>
./target/debug/fleetctl --state-dir "$STATE" audit verify
```

## Incident: audit tamper detected

`fleetctl audit verify` exits non-zero and prints the first bad sequence. Treat
the host as compromised: preserve `audit.jsonl`, snapshot the state directory,
rotate the CA if private keys may have been exposed, revoke affected leaves,
and restore from a known-good backup. Do not edit the log to “fix” it.
