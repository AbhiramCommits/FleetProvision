# onprem_rack

Models a local libvirt/QEMU rack for the on-prem half of the estate. Each
domain boots PXE-first from the bridge network, uses OVMF firmware with a
Secure Boot NVRAM template, and has a virtual TPM 2.0 so measured boot and PCR
quotes behave like real hardware.

## What it creates

* `libvirt_pool` (directory storage pool)
* `libvirt_volume` per node, cloned from the Packer qcow2 image
* `libvirt_domain` per node with `boot_device = ["network", "hd"]`, a TPM 2.0
  emulator, OVMF firmware, and a deterministic MAC address

The domains attach to an existing Linux bridge (`br-pxe` by default). DNS,
DHCP, TFTP, and HTTP are provided by `fleet-sim` in development, or by the
site's real services in production.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Rack prefix |
| `bridge_name` | string | `br-pxe` | Existing PXE bridge |
| `network_cidr` | string | `192.168.50.0/24` | PXE network |
| `node_count` | number | `3` | Domains to create |
| `mac_addresses` | list(string) | `[]` | Explicit MACs; generated if empty |
| `pool_name` | string | `fleet-images` | libvirt pool |
| `pool_path` | string | `/var/lib/libvirt/images/fleet` | Pool path |
| `image_path` | string | `/var/lib/libvirt/images/fleet/fleet-node.qcow2` | Packer image |
| `memory_mb` | number | `4096` | RAM per domain |
| `vcpu` | number | `4` | vCPUs per domain |
| `firmware` | string | `efi` | Firmware mode |
| `nvram_template` | string | OVMF_VARS_4M.ms.fd | Secure Boot NVRAM template |
| `tags` | map(string) | `{}` | Domain metadata labels |

## Outputs

| Name | Description |
| --- | --- |
| `domain_names` | Domain names |
| `mac_addresses` | MACs used for PXE reservations |
| `volume_ids` | Disk volume IDs |
| `pool_name` | Storage pool name |
