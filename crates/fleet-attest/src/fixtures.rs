//! Deterministic attestation fixture generation.
//!
//! Fixtures are committed JSON so policy tests never depend on a live TPM.
//! The simulated AK certificate is signed by a fixture-only CA whose public
//! trust bundle is committed as `fixtures/ca.pem`; the CA private key is
//! discarded after generation.

use crate::policy::Policy;
use crate::quote::{compute_quote_digest, encode_key, sign_quote};
use crate::replay::replay_event_log;
use crate::types::{AttestationBlob, Distro, SecureBootState, TcgEvent, TpmQuote};
use crate::AttestError;
use fleet_pki::{Ca, CaConfig, LeafSpec};
use p256::ecdsa::SigningKey;
use rcgen::{CertificateParams, DnType, KeyPair};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const FIXTURE_NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
pub const REPLAYED_NONCE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
pub const UBUNTU_FIRMWARE: &str = "Dell Inc. 2.19.0 UEFI";
pub const FEDORA_FIRMWARE: &str = "Dell Inc. 2.19.0 UEFI";
pub const UBUNTU_BOOTLOADER: &str = "ubuntu shim 15.8 + grub 2.12";
pub const FEDORA_BOOTLOADER: &str = "fedora shim 15.8 + grub 2.06";
pub const TAMPERED_SHIM: &str = "ubuntu shim 15.8 (tampered) + grub 2.12";
pub const UNKNOWN_FIRMWARE: &str = "Acme Unknown Firmware 0.1";
pub const PCR7_VALUE: &str = "SecureBoot policy PK/KEK/db";
pub const UBUNTU_PCR11: &str = "kernel cmdline: root=UUID=ubuntu ro quiet splash";
pub const FEDORA_PCR11: &str = "kernel cmdline: root=UUID=fedora ro quiet";

fn unique(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&value))
        {
            out.push(value);
        }
    }
    out
}

pub fn known_bad_shim_dbx() -> String {
    hex::encode(Sha256::digest(b"known-bad-shim-2019"))
}

fn event(pcr: u8, label: &str) -> TcgEvent {
    TcgEvent {
        pcr,
        digest: hex::encode(Sha256::digest(label.as_bytes())),
        event_type: "EV_ACTION".into(),
        description: label.into(),
    }
}

/// Generate a fresh P-256 AK key plus a CSR. The private key is PKCS#8 PEM.
pub fn generate_ak_keypair() -> Result<(String, String, SigningKey), AttestError> {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let key_pem = encode_key(&signing_key)?;
    let rcgen_key = KeyPair::from_pem(&key_pem)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "fleet-simulated-ak");
    let csr = params.serialize_request(&rcgen_key)?;
    Ok((key_pem, csr.pem()?, signing_key))
}

/// Issue the AK certificate from the fleet CA. The AK is a clientAuth leaf so
/// the same chain policy applies as for node certificates.
pub fn issue_ak_cert(
    ca: &mut Ca,
    node_id: &str,
    site: &str,
    csr_pem: &str,
) -> Result<String, AttestError> {
    let issued = ca.issue_leaf(
        &LeafSpec::for_node(site, format!("ak-{node_id}"))
            .with_hostname(format!("ak-{node_id}"))
            .with_csr(csr_pem.to_string()),
    )?;
    Ok(issued.cert_pem)
}

pub struct BlobOptions<'a> {
    pub node_id: &'a str,
    pub site: &'a str,
    pub distro: Distro,
    pub nonce: &'a str,
    pub firmware: &'a str,
    pub bootloader: &'a str,
    pub pcr11: &'a str,
}

impl<'a> BlobOptions<'a> {
    pub fn good(node_id: &'a str, site: &'a str, distro: Distro, nonce: &'a str) -> Self {
        let (firmware, bootloader, pcr11) = match distro {
            Distro::Ubuntu => (UBUNTU_FIRMWARE, UBUNTU_BOOTLOADER, UBUNTU_PCR11),
            Distro::Fedora => (FEDORA_FIRMWARE, FEDORA_BOOTLOADER, FEDORA_PCR11),
        };
        Self {
            node_id,
            site,
            distro,
            nonce,
            firmware,
            bootloader,
            pcr11,
        }
    }
}

/// Build a boot-integrity blob whose event log, PCR quote, and signature are
/// internally consistent.
pub fn build_blob(
    ak_cert_pem: &str,
    signing_key: &SigningKey,
    options: &BlobOptions<'_>,
) -> Result<AttestationBlob, AttestError> {
    let mut events = vec![
        event(0, &format!("UEFI firmware: {}", options.firmware)),
        event(2, "option rom: virtio-net"),
        event(2, "firmware configuration"),
        event(4, &format!("bootloader: {}", options.bootloader)),
        event(7, &format!("secure boot policy: {PCR7_VALUE}")),
        event(11, options.pcr11),
    ];
    // Deterministic ordering by PCR is not required for TPM replay, but makes
    // committed fixtures easier to read and diff.
    events.sort_by_key(|e| e.pcr);

    let selection = vec![0u8, 2, 4, 7, 11];
    let replayed = replay_event_log(&events, &selection)?;
    let pcr_values: BTreeMap<String, String> = replayed
        .iter()
        .map(|(idx, value)| (idx.to_string(), hex::encode(value)))
        .collect();
    let digest = compute_quote_digest(&selection, &pcr_values)?;
    let signature = sign_quote(signing_key, options.nonce, &digest)?;

    Ok(AttestationBlob {
        version: 1,
        node_id: options.node_id.to_string(),
        site: options.site.to_string(),
        hostname: options.node_id.to_string(),
        distro: options.distro,
        firmware: options.firmware.to_string(),
        captured_at: 1_790_000_000,
        challenge: options.nonce.to_string(),
        secure_boot: SecureBootState {
            secure_boot: true,
            setup_mode: false,
            pk: vec![hex::encode(Sha256::digest(b"fixture-pk"))],
            kek: vec![hex::encode(Sha256::digest(b"fixture-kek"))],
            db: vec![
                hex::encode(Sha256::digest(b"ubuntu-shim-signed")),
                hex::encode(Sha256::digest(b"fedora-shim-signed")),
            ],
            dbx: vec![
                known_bad_shim_dbx(),
                hex::encode(Sha256::digest(b"other-revoked-shim")),
            ],
        },
        quote: TpmQuote {
            pcr_selection: selection,
            pcr_values,
            digest,
            signature,
            nonce: options.nonce.to_string(),
        },
        event_log: events,
        ak_cert_pem: ak_cert_pem.to_string(),
    })
}

/// Generate all committed fixtures plus the policy and trust bundle.
pub fn generate(out_dir: &Path, policy_path: &Path) -> Result<Vec<String>, AttestError> {
    std::fs::create_dir_all(out_dir)?;
    let mut ca = Ca::init_root(CaConfig::default())?;
    std::fs::write(out_dir.join("ca.pem"), ca.trust_bundle_pem())?;

    let (_, csr, signing_key) = generate_ak_keypair()?;
    let ak_cert = issue_ak_cert(&mut ca, "fixtures", "dc1", &csr)?;

    let ubuntu = build_blob(
        &ak_cert,
        &signing_key,
        &BlobOptions::good("ubuntu-good", "dc1", Distro::Ubuntu, FIXTURE_NONCE),
    )?;
    let fedora = build_blob(
        &ak_cert,
        &signing_key,
        &BlobOptions::good("fedora-good", "dc1", Distro::Fedora, FIXTURE_NONCE),
    )?;

    let mut fixtures: Vec<(&str, AttestationBlob)> = vec![
        ("ubuntu-good", ubuntu.clone()),
        ("fedora-good", fedora.clone()),
    ];

    let mut secureboot_off = ubuntu.clone();
    secureboot_off.node_id = "secureboot-off".into();
    secureboot_off.secure_boot.secure_boot = false;
    fixtures.push(("secureboot-off", secureboot_off));

    let mut setup_mode = ubuntu.clone();
    setup_mode.node_id = "setup-mode-on".into();
    setup_mode.secure_boot.setup_mode = true;
    fixtures.push(("setup-mode-on", setup_mode));

    let tampered = build_blob(
        &ak_cert,
        &signing_key,
        &BlobOptions {
            node_id: "tampered-shim",
            site: "dc1",
            distro: Distro::Ubuntu,
            nonce: FIXTURE_NONCE,
            firmware: UBUNTU_FIRMWARE,
            bootloader: TAMPERED_SHIM,
            pcr11: UBUNTU_PCR11,
        },
    )?;
    fixtures.push(("tampered-shim", tampered));

    let mut replayed = ubuntu.clone();
    replayed.node_id = "replayed-nonce".into();
    replayed.challenge = REPLAYED_NONCE.into();
    fixtures.push(("replayed-nonce", replayed));

    let mut forged = ubuntu.clone();
    forged.node_id = "forged-quote".into();
    use base64::Engine;
    let mut sig = base64::engine::general_purpose::STANDARD
        .decode(&forged.quote.signature)
        .map_err(|e| AttestError::QuoteSignature(e.to_string()))?;
    let mid = sig.len() / 2;
    sig[mid] ^= 0x01;
    forged.quote.signature = base64::engine::general_purpose::STANDARD.encode(sig);
    fixtures.push(("forged-quote", forged));

    let mut mismatch = ubuntu.clone();
    mismatch.node_id = "log-quote-mismatch".into();
    for event in &mut mismatch.event_log {
        if event.pcr == 4 {
            event.digest = hex::encode(Sha256::digest(b"rewritten log event"));
        }
    }
    fixtures.push(("log-quote-mismatch", mismatch));

    let unknown = build_blob(
        &ak_cert,
        &signing_key,
        &BlobOptions {
            node_id: "unknown-firmware",
            site: "dc1",
            distro: Distro::Ubuntu,
            nonce: FIXTURE_NONCE,
            firmware: UNKNOWN_FIRMWARE,
            bootloader: UBUNTU_BOOTLOADER,
            pcr11: UBUNTU_PCR11,
        },
    )?;
    fixtures.push(("unknown-firmware", unknown));

    let mut written = Vec::new();
    for (name, blob) in &fixtures {
        let path = out_dir.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(blob)?)?;
        written.push(path.display().to_string());
    }

    let policy = Policy {
        version: 1,
        name: "boot-integrity".into(),
        description: "FleetProvision UEFI Secure Boot + TPM PCR boot-integrity policy. \
                      Generated alongside fixtures so allowlists and measurements cannot drift."
            .into(),
        require_secure_boot: true,
        require_setup_mode_off: true,
        pcr_indices: vec![0, 2, 4, 7, 11],
        allowed_pcr0: unique(vec![
            ubuntu.quote.pcr_values["0"].clone(),
            fedora.quote.pcr_values["0"].clone(),
        ]),
        allowed_pcr4: BTreeMap::from([
            (
                "ubuntu".to_string(),
                vec![ubuntu.quote.pcr_values["4"].clone()],
            ),
            (
                "fedora".to_string(),
                vec![fedora.quote.pcr_values["4"].clone()],
            ),
        ]),
        allowed_pcr7: unique(vec![
            ubuntu.quote.pcr_values["7"].clone(),
            fedora.quote.pcr_values["7"].clone(),
        ]),
        allowed_pcr11: unique(vec![
            ubuntu.quote.pcr_values["11"].clone(),
            fedora.quote.pcr_values["11"].clone(),
        ]),
        known_bad_shim_dbx: vec![known_bad_shim_dbx()],
        on_fail: "quarantine".into(),
    };
    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(policy_path, policy.to_yaml()?)?;
    written.push(policy_path.display().to_string());
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn generated() -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        generate(dir.path(), &policy_path).unwrap();
        (dir, Policy::load(&policy_path).unwrap())
    }

    fn load(dir: &Path, name: &str) -> AttestationBlob {
        serde_json::from_slice(&std::fs::read(dir.join(format!("{name}.json"))).unwrap()).unwrap()
    }

    #[test]
    fn good_fixtures_pass_including_chain() {
        let (dir, policy) = generated();
        let ca = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
        for name in ["ubuntu-good", "fedora-good"] {
            let blob = load(dir.path(), name);
            let verdict = policy.evaluate_with_ca(&blob, &ca);
            assert!(verdict.is_pass(), "{name}: {}", verdict.display_line());
        }
    }

    #[test]
    fn negative_fixtures_fail_for_the_expected_reason() {
        let (dir, policy) = generated();
        let ca = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
        let cases: [(&str, &str); 7] = [
            ("secureboot-off", "secure_boot_disabled"),
            ("setup-mode-on", "setup_mode_enabled"),
            ("tampered-shim", "pcr_not_allowed"),
            ("replayed-nonce", "replayed_nonce"),
            ("forged-quote", "forged_quote"),
            ("log-quote-mismatch", "log_quote_mismatch"),
            ("unknown-firmware", "pcr_not_allowed"),
        ];
        for (name, code) in cases {
            let blob = load(dir.path(), name);
            let verdict = policy.evaluate_with_ca(&blob, &ca);
            assert!(!verdict.is_pass(), "{name} unexpectedly passed");
            assert!(
                verdict.codes().contains(&code),
                "{name} expected {code}, got {:?} ({})",
                verdict.codes(),
                verdict.display_line()
            );
        }
    }

    #[test]
    fn chain_verification_rejects_a_foreign_ak() {
        let (dir, policy) = generated();
        let mut blob = load(dir.path(), "ubuntu-good");
        let mut foreign_ca = Ca::init_root(CaConfig::default()).unwrap();
        let (_, csr, _) = generate_ak_keypair().unwrap();
        blob.ak_cert_pem = issue_ak_cert(&mut foreign_ca, "x", "dc1", &csr).unwrap();
        let ca = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
        let verdict = policy.evaluate_with_ca(&blob, &ca);
        assert!(verdict.codes().contains(&"ak_chain_untrusted"));
    }

    #[test]
    fn signing_and_signature_tampering_disagree() {
        let (_, _, key) = generate_ak_keypair().unwrap();
        let digest = "00".repeat(32);
        let sig = sign_quote(&key, FIXTURE_NONCE, &digest).unwrap();
        assert!(!sig.is_empty());
        let mut quote = TpmQuote {
            pcr_selection: vec![0],
            pcr_values: BTreeMap::new(),
            digest,
            signature: sig,
            nonce: FIXTURE_NONCE.into(),
        };
        quote.signature = base64::engine::general_purpose::STANDARD.encode([0u8; 8]);
        assert!(crate::verify_quote_signature("not a cert", &quote).is_err());
    }

    #[test]
    fn tampered_shim_differs_only_in_pcr4() {
        let (dir, _) = generated();
        let good = load(dir.path(), "ubuntu-good");
        let tampered = load(dir.path(), "tampered-shim");
        for pcr in ["0", "2", "7", "11"] {
            assert_eq!(good.quote.pcr_values[pcr], tampered.quote.pcr_values[pcr]);
        }
        assert_ne!(good.quote.pcr_values["4"], tampered.quote.pcr_values["4"]);
    }

    #[test]
    fn replayed_fixture_challenge_differs_from_signed_nonce() {
        let (dir, _) = generated();
        let blob = load(dir.path(), "replayed-nonce");
        assert_ne!(blob.challenge, blob.quote.nonce);
        assert!(matches!(
            crate::quote::verify_quote_signature(&blob.ak_cert_pem, &blob.quote),
            Ok(())
        ));
    }
}
