# envs/onprem

The on-prem rack: libvirt domains with PXE-first boot, OVMF Secure Boot
firmware, and virtual TPM 2.0.

Prerequisites on the hypervisor host:

* libvirt + QEMU with UEFI/OVMF (`OVMF_VARS_4M.ms.fd` for Secure Boot)
* an existing bridge (`br-pxe`) connected to the provisioning VLAN
* the Packer qcow2 image at `image_path`
* the `dmacvicar/libvirt` provider

Validate without a hypervisor:

```bash
terraform init -backend=false
terraform validate
```

Plan/apply requires `qemu:///system` access. There is no AWS equivalent here;
applying creates local VM disks and domains.
