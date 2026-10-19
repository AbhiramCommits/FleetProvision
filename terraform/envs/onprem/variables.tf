variable "libvirt_uri" {
  description = "libvirt connection URI."
  type        = string
  default     = "qemu:///system"
}

variable "rack_name" {
  description = "Rack name prefix."
  type        = string
  default     = "rack-a"
}

variable "node_count" {
  description = "Number of libvirt domains."
  type        = number
  default     = 3
}

variable "bridge_name" {
  description = "Existing PXE bridge."
  type        = string
  default     = "br-pxe"
}

variable "image_path" {
  description = "Packer-built qcow2 image."
  type        = string
  default     = "/var/lib/libvirt/images/fleet/fleet-node.qcow2"
}
