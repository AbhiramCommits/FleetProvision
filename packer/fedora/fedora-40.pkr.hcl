packer {
  required_version = ">= 1.10.0"

  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

variable "output_dir" {
  type    = string
  default = "out"
}

variable "fleet_site" {
  type    = string
  default = "dc1"
}

variable "fleet_trust_bundle" {
  type      = string
  default   = ""
  sensitive = true
}

variable "fleet_agent_binary" {
  type    = string
  default = "../../target/release/fleet-agent"
}

source "qemu" "fedora_40" {
  iso_url          = "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Server/x86_64/iso/Fedora-Server-dvd-x86_64-40-1.14.iso"
  iso_checksum     = "sha256:32d9ab1798fc8106a0b06e873bdcd83a3efea8412c9401dfe4097347ed0cfc65"
  vm_name          = "fedora-40.qcow2"
  output_directory = var.output_dir

  http_directory = "../../provisioning"
  http_port_min  = 8200
  http_port_max  = 8299

  memory      = 2048
  cpus        = 2
  disk_size   = "20480"
  format      = "qcow2"
  accelerator = "kvm"
  headless    = true
  net_device  = "virtio-net"

  boot_wait = "10s"
  boot_command = [
    "<up><tab><wait>",
    " inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/kickstart/fedora.ks inst.text inst.cmdline<enter>"
  ]

  ssh_username = "fedora"
  ssh_password = "fedora"
  ssh_timeout  = "60m"

  shutdown_command = "echo 'fedora' | sudo -S shutdown -P now"
}

build {
  name    = "fedora-40"
  sources = ["source.qemu.fedora_40"]

  provisioner "file" {
    source      = var.fleet_agent_binary
    destination = "/tmp/fleet-agent"
  }

  provisioner "ansible" {
    playbook_file = "../../ansible/playbooks/fleet_node.yml"
    groups        = ["fleet_nodes"]
    use_proxy     = false
    extra_arguments = [
      "--extra-vars",
      "fleet_node_agent_source=/tmp/fleet-agent fleet_node_site=${var.fleet_site} fleet_node_trust_bundle=${var.fleet_trust_bundle} fleet_node_agent_distro=fedora fleet_node_manage_services=false"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo systemctl enable fleet-agent-renew.timer || true",
      "sudo rm -f /tmp/fleet-agent",
      "sudo cloud-init clean --logs --seed || true",
      "sudo truncate -s 0 /etc/machine-id"
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_dir}/fedora-40-manifest.json"
    strip_path = true
  }

  post-processor "shell-local" {
    inline = [
      "mkdir -p ${var.output_dir}",
      "if command -v sha256sum >/dev/null 2>&1; then sha256sum ${var.output_dir}/fedora-40.qcow2 > ${var.output_dir}/fedora-40.qcow2.sha256; else shasum -a 256 ${var.output_dir}/fedora-40.qcow2 > ${var.output_dir}/fedora-40.qcow2.sha256; fi"
    ]
  }
}
