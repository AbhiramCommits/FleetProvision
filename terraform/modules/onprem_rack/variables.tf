variable "name" {
  description = "Rack name prefix."
  type        = string
}

variable "bridge_name" {
  description = "Existing Linux bridge for the on-prem rack (pxe VLAN)."
  type        = string
  default     = "br-pxe"
}

variable "network_cidr" {
  description = "PXE network CIDR."
  type        = string
  default     = "192.168.50.0/24"
}

variable "node_count" {
  description = "Number of bare-metal domains to create."
  type        = number
  default     = 3

  validation {
    condition     = var.node_count > 0 && var.node_count <= 64
    error_message = "node_count must be between 1 and 64."
  }
}

variable "mac_addresses" {
  description = "Optional explicit MAC list; generated when empty."
  type        = list(string)
  default     = []
}

variable "pool_name" {
  description = "libvirt storage pool for node volumes."
  type        = string
  default     = "fleet-images"
}

variable "pool_path" {
  description = "Filesystem path backing the libvirt storage pool."
  type        = string
  default     = "/var/lib/libvirt/images/fleet"
}

variable "image_path" {
  description = "Packer-built qcow2 image used as the volume source."
  type        = string
  default     = "/var/lib/libvirt/images/fleet/fleet-node.qcow2"
}

variable "memory_mb" {
  description = "Memory per domain in MiB."
  type        = number
  default     = 4096
}

variable "vcpu" {
  description = "vCPUs per domain."
  type        = number
  default     = 4
}

variable "firmware" {
  description = "libvirt firmware mode. Use efi with a secure-boot OVMF build."
  type        = string
  default     = "efi"
}

variable "nvram_template" {
  description = "OVMF_VARS template; use the .ms.fd variant for Secure Boot."
  type        = string
  default     = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
}

variable "tags" {
  description = "Labels written into domain metadata."
  type        = map(string)
  default     = {}
}
