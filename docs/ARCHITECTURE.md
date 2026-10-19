# Architecture

## Trust boundaries

```
                    bootstrap token (HMAC, single-use, TTL)
 node (no identity) ──────────────────────────────────────► fleetd :8444
        │                                                      │
        │ CSR + attestation (nonce-bound TPM quote)             │ policy
        ▼                                                      ▼
 fleet CA (root → intermediate) ◄──── sign CSR ─────── policy engine
        │
        │ 90-day leaf (clientAuth, SAN DNS + fleet:// URI)
        ▼
 node mTLS identity ──────────► fleetd :8443 (CRL checked in verifier)
        │
        └─ 802.1X authenticator (chain + CRL + attestation) → VLAN 100 / 666 / reject
```

Human operators never present node certificates. They obtain RS256 JWTs from
the OIDC issuer (device-authorization grant) or present a signed SAML assertion
to the SAML verifier; `fleetd` authorizes on `fleet-admin` / `fleet-operator`
groups on `:9443`. Node certificates are rejected on operator endpoints and
operator bearers are rejected on the machine enrollment listener.

## Enrollment state machine

```
            token + attestation pass             leaf issued
  Pending ──────────────────────► Attested ──────────────────► Enrolled
     │                                │                            │
     │ attestation fail               │ fail                       │ revoke
     ▼                                ▼                            ▼
  Quarantined ◄──────────────────────┘                         Revoked
     │
     └────────── remediation + fresh token ──► Attested
```

`Revoked` is terminal for an identity. Re-imaging a node creates a new identity
(or the operator explicitly clears the record and issues fresh tokens). The
state machine is enforced in `fleetd::store::Store::upsert`, and every transition
is persisted to `state/nodes.json` before the HTTP response.

## Certificate lifecycle

| Object | Algorithm | Validity | Notes |
| --- | --- | --- | --- |
| Root CA | ECDSA P-256 | 3,650 days | `CA:TRUE`, pathlen 1, keyCertSign + cRLSign |
| Intermediate | ECDSA P-256 | 1,825 days | `CA:TRUE`, pathlen 0, active signing key |
| Node leaf | ECDSA P-256 | 90 days | `clientAuth`, DNS `<host>.fleet.internal`, URI `fleet://<site>/<node>` |
| fleetd leaf | ECDSA P-256 | 90 days | `serverAuth`, `localhost`/`127.0.0.1` plus `fleetd.fleet.internal` |
| AK leaf (sim) | ECDSA P-256 | 90 days | `clientAuth`; signs TPM quotes |
| CRL | ECDSA P-256 | 168 hours | v2, reason codes, `nextUpdate` enforced |

Timeline for a leaf: issued at `t=0`, renewal threshold at `t=60 days` (2/3 of
90), hard expiry at `t=90`. `fleet-agent` checks the threshold daily via
`fleet-agent-renew.timer`; renewal re-keys and revokes the old serial as
`superseded`, so the old key cannot be used after the new certificate is issued.

Intermediate rotation (`fleetctl ca rotate`) signs a new intermediate with the
root and appends it to the trust bundle. The retired intermediate is kept in
`trust-bundle.pem` so unexpired leaves continue to chain. The verifier rebuilds
its chain set per handshake from the trust bundle, so a restart picks up the
rotated bundle.

## CRL distribution and enforcement

* `fleetd` writes `state/crl.pem` on every revocation and rotates the
  `fleet_crl_number`.
* Nodes fetch the CRL over mTLS at `GET /v1/crl`.
* The custom `ClientCertVerifier` reads the in-memory `CrlStore` on every
  handshake: stale CRL → `ExpiredRevocationList`, revoked serial → `Revoked`,
  both fail closed before any HTTP handler runs.
* The 802.1X authenticator performs the same check with an optional clock
  offset used to test expiry.
* A CRL older than `nextUpdate` is never treated as “probably fine”; the
  distinct `StaleCrl` error is surfaced in tests and metrics.

## PCR policy rationale

| PCR | Measures | Why the policy pins it |
| --- | --- | --- |
| 0 | UEFI firmware / SRTM | Detects unknown or tampered firmware images |
| 2 | Option ROMs and firmware configuration | Detects unexpected boot devices or config changes |
| 4 | Shim + GRUB / bootloader | Detects a tampered shim or bootloader chain; per-distro allowlist |
| 7 | Secure Boot policy (PK/KEK/db/dbx) | Detects disabled Secure Boot, Setup Mode, or missing dbx revocations |
| 11 | Kernel command line / UKI | Detects injected kernel arguments or an unexpected kernel image |

Evaluation order in `fleet_attest::Policy`:

1. Nonce equality (`challenge == quote.nonce`) → `replayed_nonce`.
2. Secure Boot on / Setup Mode off / PK+KEK present.
3. Every known-bad shim hash present in dbx.
4. All policy PCRs quoted.
5. SHA-256 extend replay of the TCG event log, compared with the quote
   (`log_quote_mismatch`).
6. Quote digest covers the quoted PCR values (`quote_digest_mismatch`).
7. ECDSA quote signature verifies under the AK certificate (`forged_quote`).
8. AK certificate chains to the fleet CA with clientAuth EKU
   (`ak_chain_untrusted`).
9. PCR0/PCR4/PCR7/PCR11 values are in their allowlists (`pcr_not_allowed`).

Any violation sets the node to `Quarantined`, consumes the bootstrap token, and
returns HTTP 403 with `violations`; no certificate is issued.

## Bootstrap tokens

Token format: `base64url(JSON payload) + "." + base64url(HMAC-SHA256)`. The
payload is `{v,id,node_id,site,exp}`. The server keeps the 32-byte key in
`state/token-key.hex` (mode 0600) and a persisted used-token set in
`state/tokens.json`, so replay survives restart (HTTP 409). Tokens are consumed
on the first enrollment attempt, including attestation failures, preventing
oracle-style retries.

The simulated AK provisioning step also uses the token but does not consume it:
`POST /v1/ak` issues a short-lived AK certificate for a CSR. In production this
would be replaced by a vendor EK/AK chain baked into the image.

## Audit chain

`state/audit.jsonl` records:

```json
{"seq":1,"ts":...,"actor":"...","action":"...","subject":"...","detail":"...",
 "prev_hash":"<sha256 of previous record>","record_hash":"<sha256>"}
```

`record_hash = SHA-256(seq|ts|actor|action|subject|detail|prev_hash)`.
`fleetctl audit verify` walks the chain, checks sequence continuity, `prev_hash`
links, and recomputed hashes. A byte flip, deletion, insertion, or JSON
corruption yields `TAMPERED at sequence N`. The log is local and append-only;
production should anchor the last hash in an external append-only store.

## 802.1X-shaped handshake

The simulator uses a JSON-line protocol over TCP with real cryptographic checks:

1. Supplicant sends `eapol_start`.
2. Authenticator requests identity.
3. Supplicant presents its node certificate.
4. Authenticator verifies chain + EKU, checks the CRL, and matches the SAN
   node-id to the claimed identity.
5. Authenticator sends a fresh 128-bit challenge.
6. Supplicant signs it with the node private key (P-256 ECDSA).
7. Authenticator verifies possession and the attestation verdict, then returns
   VLAN 100 (pass), VLAN 666 (quarantine), or a rejection (unknown/revoked/stale).

## Storage layout

```
state/
  ca.json                  CA config, revocation list, CRL metadata
  root-key.pem             mode 0600
  intermediate-<serial>-key.pem
  root-cert.pem
  trust-bundle.pem         root + all intermediates
  crl.pem
  nodes.json               node records and states
  tokens.json              issued/used bootstrap tokens
  token-key.hex            HMAC key, mode 0600
  audit.jsonl              hash-chained audit records
  server/fleetd.{crt,key,chain}.pem
  nodes/<node>/{node.crt,node.key,node-chain,node.csr}.pem
```

## Failure semantics

* HTTP listener failure: request fails; state is only persisted after the
  certificate is issued.
* CA issuance failure: 400 `csr_invalid`, token remains unconsumed for CSR
  errors (retryable) but attestation failures consume the token.
* Revocation: CRL is re-signed and swapped before the response; the next
  handshake fails.
* Restart: CA, node inventory, tokens, CRL, and audit log reload from disk.
* Stale CRL or unknown issuer: handshake fails closed; no HTTP layer runs.
