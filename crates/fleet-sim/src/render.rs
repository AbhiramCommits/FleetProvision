//! Render per-MAC iPXE scripts, Kickstart, and cloud-init from the inventory.

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Inventory {
    pub site: String,
    pub api: String,
    pub enroll_url: String,
    pub tftp_server: String,
    pub http_server: String,
    pub https_server: String,
    pub token_url: String,
    pub nodes: Vec<InventoryNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InventoryNode {
    pub id: String,
    pub mac: String,
    pub distro: String,
    pub vlan: u16,
    pub role: String,
}

impl Inventory {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading inventory {}", path.display()))?;
        let inventory: Inventory = serde_yaml::from_str(&raw)?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.nodes.is_empty() {
            bail!("inventory has no nodes");
        }
        let mut macs = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for node in &self.nodes {
            if !is_mac(&node.mac) {
                bail!("node {} has invalid MAC {}", node.id, node.mac);
            }
            if !macs.insert(node.mac.to_ascii_lowercase()) {
                bail!("duplicate MAC {}", node.mac);
            }
            if !ids.insert(node.id.clone()) {
                bail!("duplicate node id {}", node.id);
            }
            if !matches!(node.distro.as_str(), "ubuntu" | "fedora") {
                bail!("node {} has unknown distro {}", node.id, node.distro);
            }
        }
        Ok(())
    }
}

fn is_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

#[derive(Debug, Serialize)]
pub struct RenderManifest {
    pub site: String,
    pub nodes: Vec<RenderedNode>,
}

#[derive(Debug, Serialize)]
pub struct RenderedNode {
    pub id: String,
    pub mac: String,
    pub distro: String,
    pub ipxe: String,
    pub boot: String,
}

/// Render everything and return a manifest. Tokens are read from `token_dir`
/// as `<node>.token`; the generated boot files fetch them over HTTPS with the
/// CA bundle pinned, they are never embedded in the boot loader script.
pub fn render(
    inventory: &Inventory,
    out_dir: &Path,
    token_dir: &Path,
    ca_bundle_path: &Path,
) -> anyhow::Result<RenderManifest> {
    let ca_bundle = std::fs::read_to_string(ca_bundle_path)
        .with_context(|| format!("reading CA bundle {}", ca_bundle_path.display()))?;
    if !ca_bundle.contains("BEGIN CERTIFICATE") {
        bail!(
            "{} does not look like a PEM trust bundle",
            ca_bundle_path.display()
        );
    }
    std::fs::create_dir_all(out_dir.join("ipxe"))?;
    std::fs::create_dir_all(out_dir.join("kickstart"))?;
    std::fs::create_dir_all(out_dir.join("cloud-init"))?;
    std::fs::create_dir_all(out_dir.join("tokens"))?;

    let mut rendered = Vec::new();
    for node in &inventory.nodes {
        let token_path = token_dir.join(format!("{}.token", node.id));
        let token = std::fs::read_to_string(&token_path).with_context(|| {
            format!(
                "missing bootstrap token for {} at {}; run `fleetctl token create --out` first",
                node.id,
                token_path.display()
            )
        })?;
        let token = token.trim();
        if token.len() < 16 {
            bail!("token for {} is too short", node.id);
        }
        std::fs::write(
            out_dir.join("tokens").join(format!("{}.token", node.id)),
            token,
        )?;

        let boot_url = format!(
            "{}/boot/{}",
            inventory.http_server.trim_end_matches('/'),
            node.id
        );
        let ipxe = format!(
            "#!ipxe\n# Rendered for {id} ({mac}, {distro}, vlan {vlan})\nset base {http}\n\
             set node {id}\nset ks {boot}\nchain --autofree ${{ks}} || goto failed\n\n\
             :failed\necho Failed to fetch {boot}\nshell\n",
            id = node.id,
            mac = node.mac,
            distro = node.distro,
            vlan = node.vlan,
            http = inventory.http_server.trim_end_matches('/'),
            boot = boot_url,
        );
        std::fs::write(
            out_dir
                .join("ipxe")
                .join(format!("{}.ipxe", mac_hyphen(&node.mac))),
            &ipxe,
        )?;

        let (kind, _boot) = if node.distro == "fedora" {
            let ks = kickstart(node, inventory, &ca_bundle)?;
            std::fs::write(
                out_dir.join("kickstart").join(format!("{}.ks", node.id)),
                &ks,
            )?;
            ("kickstart", ks)
        } else {
            let ci = cloud_init(node, inventory, &ca_bundle)?;
            std::fs::write(
                out_dir.join("cloud-init").join(format!("{}.yaml", node.id)),
                &ci,
            )?;
            ("cloud-init", ci)
        };
        rendered.push(RenderedNode {
            id: node.id.clone(),
            mac: node.mac.clone(),
            distro: node.distro.clone(),
            ipxe: format!("ipxe/{}.ipxe", mac_hyphen(&node.mac)),
            boot: format!("{kind}/{}", node.id),
        });
    }

    let manifest = RenderManifest {
        site: inventory.site.clone(),
        nodes: rendered,
    };
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

pub fn mac_hyphen(mac: &str) -> String {
    mac.replace(':', "-").to_ascii_lowercase()
}

fn kickstart(
    node: &InventoryNode,
    inventory: &Inventory,
    ca_bundle: &str,
) -> anyhow::Result<String> {
    Ok(format!(
        r#"#version=F40
# Rendered by fleet-sim render-ipxe for {id}
text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --device=link --activate
rootpw --lock
user --name=fleet --groups=wheel --plaintext --password=fleet
selinux --enforcing
firewall --enabled --service=ssh
services --enabled=sshd,chronyd,qemu-guest-agent
bootloader --location=mbr --boot-drive=vda
zerombr
clearpart --all --initlabel --drives=vda
autopart --type=plain --fstype=xfs
reboot

%packages
@^server-product-environment
chrony
qemu-guest-agent
curl
%end

%post --erroronfail
set -euxo pipefail
install -d -m 0755 /etc/fleet-agent /etc/fleet /var/lib/fleet-agent
chmod 0700 /var/lib/fleet-agent
cat > /etc/fleet/trust-bundle.pem <<'FLEETCA'
{ca_bundle}
FLEETCA
chmod 0644 /etc/fleet/trust-bundle.pem
# Fetch the single-use token over HTTPS with the pinned CA bundle.
curl --fail --silent --show-error --cacert /etc/fleet/trust-bundle.pem \
  -o /etc/fleet/bootstrap-token "{token_url}/{id}.token"
chmod 0600 /etc/fleet/bootstrap-token
/usr/local/bin/fleet-agent enroll \
  --enroll-url "{enroll_url}" \
  --node-id "{id}" \
  --site "{site}" \
  --token "$(cat /etc/fleet/bootstrap-token)" \
  --state-dir /var/lib/fleet-agent \
  --ca-bundle /etc/fleet/trust-bundle.pem \
  --distro fedora
rm -f /etc/fleet/bootstrap-token
systemctl enable --now fleet-agent-renew.timer
%end
"#,
        id = node.id,
        ca_bundle = ca_bundle.trim_end(),
        token_url = inventory.token_url.trim_end_matches('/'),
        enroll_url = inventory.enroll_url,
        site = inventory.site,
    ))
}

fn cloud_init(
    node: &InventoryNode,
    inventory: &Inventory,
    ca_bundle: &str,
) -> anyhow::Result<String> {
    Ok(format!(
        r#"#cloud-config
# Rendered by fleet-sim render-ipxe for {id}
hostname: {id}
fqdn: {id}.fleet.internal
manage_etc_hosts: true

packages:
  - ca-certificates
  - chrony
  - curl

write_files:
  - path: /etc/fleet-agent/trust-bundle.pem
    owner: root:root
    permissions: "0644"
    content: |
{indented_ca}

runcmd:
  - install -d -m 0755 /etc/fleet-agent /var/lib/fleet-agent
  - chmod 0700 /var/lib/fleet-agent
  - curl --fail --silent --show-error --cacert /etc/fleet-agent/trust-bundle.pem -o /etc/fleet-agent/bootstrap-token "{token_url}/{id}.token"
  - chmod 0600 /etc/fleet-agent/bootstrap-token
  - /usr/local/bin/fleet-agent enroll --enroll-url "{enroll_url}" --node-id "{id}" --site "{site}" --token "$(cat /etc/fleet-agent/bootstrap-token)" --state-dir /var/lib/fleet-agent --ca-bundle /etc/fleet-agent/trust-bundle.pem --distro {distro}
  - rm -f /etc/fleet-agent/bootstrap-token
  - systemctl enable --now fleet-agent-renew.timer

final_message: "FleetProvision node {id} bootstrapped after $UPTIME seconds"
"#,
        id = node.id,
        indented_ca = ca_bundle
            .trim_end()
            .lines()
            .map(|line| format!("      {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
        token_url = inventory.token_url.trim_end_matches('/'),
        enroll_url = inventory.enroll_url,
        site = inventory.site,
        distro = node.distro,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> Inventory {
        Inventory {
            site: "dc1".into(),
            api: "https://fleetd.fleet.internal:8443".into(),
            enroll_url: "https://fleetd.fleet.internal:8444".into(),
            tftp_server: "192.168.50.2".into(),
            http_server: "http://192.168.50.2:8080".into(),
            https_server: "https://192.168.50.2:8443".into(),
            token_url: "https://192.168.50.2:8443/tokens".into(),
            nodes: vec![
                InventoryNode {
                    id: "n1".into(),
                    mac: "52:54:00:5f:6c:01".into(),
                    distro: "ubuntu".into(),
                    vlan: 100,
                    role: "worker".into(),
                },
                InventoryNode {
                    id: "n2".into(),
                    mac: "52:54:00:5f:6c:02".into(),
                    distro: "fedora".into(),
                    vlan: 100,
                    role: "worker".into(),
                },
            ],
        }
    }

    #[test]
    fn mac_validation() {
        assert!(is_mac("52:54:00:5f:6c:01"));
        assert!(!is_mac("52:54:00:5f:6c"));
        assert!(!is_mac("zz:54:00:5f:6c:01"));
    }

    #[test]
    fn duplicate_macs_are_rejected() {
        let mut inv = inventory();
        inv.nodes[1].mac = inv.nodes[0].mac.clone();
        assert!(inv.validate().is_err());
    }

    #[test]
    fn render_produces_both_boot_paths_and_pins_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = dir.path().join("tokens-in");
        std::fs::create_dir_all(&tokens).unwrap();
        std::fs::write(tokens.join("n1.token"), "token-for-n1-0123456789").unwrap();
        std::fs::write(tokens.join("n2.token"), "token-for-n2-0123456789").unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let out = dir.path().join("out");
        let manifest = render(&inventory(), &out, &tokens, &ca_path).unwrap();
        assert_eq!(manifest.nodes.len(), 2);
        let ks = std::fs::read_to_string(out.join("kickstart/n2.ks")).unwrap();
        assert!(ks.contains("--cacert /etc/fleet/trust-bundle.pem"));
        assert!(ks.contains("https://192.168.50.2:8443/tokens/n2.token"));
        assert!(!ks.contains("token-for-n2"));
        let ci = std::fs::read_to_string(out.join("cloud-init/n1.yaml")).unwrap();
        assert!(ci.contains("fleet-agent enroll"));
        assert!(ci.contains("BEGIN CERTIFICATE"));
        let ipxe = std::fs::read_to_string(out.join("ipxe/52-54-00-5f-6c-01.ipxe")).unwrap();
        assert!(ipxe.contains("#!ipxe"));
    }

    #[test]
    fn missing_token_fails_with_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let tokens = dir.path().join("tokens-in");
        std::fs::create_dir_all(&tokens).unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let err = render(&inventory(), &dir.path().join("out"), &tokens, &ca_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing bootstrap token"), "{err}");
    }
}
