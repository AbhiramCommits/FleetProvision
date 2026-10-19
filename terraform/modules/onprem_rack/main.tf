locals {
  macs = length(var.mac_addresses) > 0 ? var.mac_addresses : [
    for i in range(var.node_count) : format("52:54:00:5f:6c:%02x", i + 1)
  ]
  metadata = jsonencode(merge(var.tags, {
    fleet_site = lookup(var.tags, "fleet_site", "dc1")
    boot       = "pxe-first"
  }))
}

resource "libvirt_pool" "images" {
  name = var.pool_name
  type = "dir"
  path = var.pool_path
}

resource "libvirt_volume" "node" {
  count = var.node_count

  name   = "${var.name}-node-${count.index + 1}.qcow2"
  pool   = libvirt_pool.images.name
  source = var.image_path
  format = "qcow2"
}

resource "libvirt_domain" "node" {
  count = var.node_count

  name       = "${var.name}-node-${count.index + 1}"
  memory     = var.memory_mb
  vcpu       = var.vcpu
  type       = "qemu"
  machine    = "q35"
  firmware   = var.firmware
  autostart  = true
  running    = true
  qemu_agent = true

  nvram {
    file     = "${var.pool_path}/${var.name}-node-${count.index + 1}_VARS.fd"
    template = var.nvram_template
  }

  # Virtual TPM 2.0 is required for Measured Boot and PCR quotes.
  tpm {
    backend_type    = "emulator"
    backend_version = "2.0"
  }

  # PXE first, then the Packer-installed disk. The iPXE script chains to the
  # per-MAC HTTP endpoint and selects Kickstart or cloud-init.
  boot_device {
    dev = ["network", "hd"]
  }

  disk {
    volume_id = libvirt_volume.node[count.index].id
  }

  network_interface {
    bridge         = var.bridge_name
    mac            = local.macs[count.index]
    wait_for_lease = false
  }

  metadata = local.metadata
}
