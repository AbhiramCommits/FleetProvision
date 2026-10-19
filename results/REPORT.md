# FleetProvision benchmark report

Generated: 2026-10-19 20:57:31.482426 +00:00:00

## Machine

| OS | CPU | Rust | Terraform | Packer | ansible-lint |
|---|---|---|---|---|---|
| Darwin 27.0.0 | Apple M3 | rustc 1.99.1 (58cf8f9c3 2026-10-13) | Terraform v1.16.5 | Packer v1.16.1 | ansible-lint 26.10.1 using ansible-core:2.21.5 ansible-compat:26.10.0 ruamel-yaml:0.19.1 |

## CA issuance

| certs | throughput | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1000 | 7664.5/s | 0.09 ms | 0.09 ms | 0.15 ms | 0.30 ms |

## mTLS

| handshakes | p50 | p95 | revoked attempts | rejection p50 | rejection p95 | handshake failures |
|---|---|---|---|---|---|---|
| 500 | 0.30 ms | 0.42 ms | 100 | 0.43 ms | 0.52 ms | 100 |

## Enrollment

| nodes | success | wall | nodes/sec | per-node p50 | p95 |
|---|---|---|---|---|---|
| 20 | 20 | 427 ms | 46.8 | 138.0 ms | 214.0 ms |
| 100 | 100 | 1388 ms | 72.0 | 695.0 ms | 1152.0 ms |

## Attestation policy

1000 evaluations, p50 0.260 ms, p95 0.270 ms. Fixtures: 2 pass, 7 fail.

| fixture | verdict |
|---|---|
| fedora-good.json | PASS |
| forged-quote.json | forged_quote |
| log-quote-mismatch.json | log_quote_mismatch |
| replayed-nonce.json | replayed_nonce |
| secureboot-off.json | secure_boot_disabled |
| setup-mode-on.json | setup_mode_enabled |
| tampered-shim.json | pcr_not_allowed |
| ubuntu-good.json | PASS |
| unknown-firmware.json | pcr_not_allowed |

## Provisioning simulation

| nodes | success | wall | VLAN100 | VLAN666 | rejected | boot-to-enrolled p50 | p95 |
|---|---|---|---|---|---|---|---|
| 20 | 20 | 270 ms | 20 | 0 | 0 | 123 ms | 188 ms |
| 100 | 100 | 1115 ms | 100 | 0 | 0 | 560 ms | 981 ms |

## 802.1X outcomes

VLAN 100: 1, VLAN 666: 1, rejected: 1 (p50 0.80 ms).

## Failure injection

6 of 6 deliberate failures failed closed.

| scenario | expected | observed | failed closed |
|---|---|---|---|
| dhcp unknown MAC | NAK | DHCP NAK: unknown mac | true |
| tftp file not found | ERROR code 1 | TFTP file not found: File not found | true |
| http 404 kickstart | 404 | HTTP 404 for /kickstart/missing.ks | true |
| truncated TLS handshake | server stays up and counts a handshake failure | healthz_ok=true handshake_failures=1 | true |
| expired CRL | stale_crl rejection | Rejected { reason: "stale_crl" } | true |
| revoked supplicant | revoked rejection | Rejected { reason: "revoked" } | true |

## Totals

* Tests: 117
* Terraform resources planned: 27
* Modules/environments validated: 5
* Attestation fixtures: 9
