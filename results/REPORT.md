# FleetProvision benchmark report

Generated: 2026-10-19 20:51:52.662618 +00:00:00

## Machine

| OS | CPU | Rust | Terraform | Packer | ansible-lint |
|---|---|---|---|---|---|
| Darwin 27.0.0 | Apple M3 | rustc 1.99.1 (58cf8f9c3 2026-10-13) | Terraform v1.16.5 | Packer v1.16.1 | ansible-lint 26.10.1 using ansible-core:2.21.5 ansible-compat:26.10.0 ruamel-yaml:0.19.1 |

## CA issuance

| certs | throughput | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1000 | 1192.7/s | 0.17 ms | 0.69 ms | 8.60 ms | 42.89 ms |

## mTLS

| handshakes | p50 | p95 | revoked attempts | rejection p50 | rejection p95 | handshake failures |
|---|---|---|---|---|---|---|
| 500 | 1.34 ms | 3.83 ms | 100 | 2.07 ms | 11.02 ms | 100 |

## Enrollment

| nodes | success | wall | nodes/sec | per-node p50 | p95 |
|---|---|---|---|---|---|
| 20 | 20 | 738 ms | 27.1 | 174.0 ms | 272.0 ms |
| 100 | 100 | 1600 ms | 62.5 | 861.0 ms | 1346.0 ms |

## Attestation policy

1000 evaluations, p50 0.590 ms, p95 0.770 ms. Fixtures: 2 pass, 7 fail.

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
| 20 | 20 | 339 ms | 20 | 0 | 0 | 127 ms | 202 ms |
| 100 | 100 | 1268 ms | 100 | 0 | 0 | 659 ms | 1124 ms |

## 802.1X outcomes

VLAN 100: 1, VLAN 666: 1, rejected: 1 (p50 1.70 ms).

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
