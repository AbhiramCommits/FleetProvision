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

source "qemu" "ubuntu_2404" {
  iso_url          = "https://releases.ubuntu.com/24.04/ubuntu-24.04.5-live-server-amd64.iso"
  iso_checksum     = "sha256:97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8"
  vm_name          = "ubuntu-2404.qcow2"
  output_directory = var.output_dir

  http_directory = "../../provisioning"
  http_port_min  = 8100
  http_port_max  = 8199

  memory      = 2048
  cpus        = 2
  disk_size   = "20480"
  format      = "qcow2"
  accelerator = "kvm"
  headless    = true
  net_device  = "virtio-net"

  boot_wait = "5s"
  boot_command = [
    "<esc><wait>",
    "e<wait>",
    "<down><down><down><end>",
    " autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/cloud-init/ <wait>",
    "<f10>"
  ]

  ssh_username = "ubuntu"
  ssh_password = "ubuntu"
  ssh_timeout  = "40m"

  shutdown_command = "echo 'ubuntu' | sudo -S shutdown -P now"
}

build {
  name    = "ubuntu-2404"
  sources = ["source.qemu.ubuntu_2404"]

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
      "fleet_node_agent_source=/tmp/fleet-agent fleet_node_site=${var.fleet_site} fleet_node_trust_bundle=${var.fleet_trust_bundle} fleet_node_manage_services=false"
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
    output     = "${var.output_dir}/ubuntu-2404-manifest.json"
    strip_path = true
  }

  post-processor "shell-local" {
    inline = [
      "mkdir -p ${var.output_dir}",
      "if command -v sha256sum >/dev/null 2>&1; then sha256sum ${var.output_dir}/ubuntu-2404.qcow2 > ${var.output_dir}/ubuntu-2404.qcow2.sha256; else shasum -a 256 ${var.output_dir}/ubuntu-2404.qcow2 > ${var.output_dir}/ubuntu-2404.qcow2.sha256; fi"
    ]
  }
}
