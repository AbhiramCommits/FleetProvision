variable "name" {
  description = "Node name (also used as the fleet identity)."
  type        = string
}

variable "ami" {
  description = "AMI produced by the Packer Ubuntu/Fedora build."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.medium"
}

variable "subnet_id" {
  description = "Private subnet for the node."
  type        = string
}

variable "security_group_ids" {
  description = "Security groups (typically the fleetd SG)."
  type        = list(string)
}

variable "site" {
  description = "Fleet site label written to tags and the certificate URI SAN."
  type        = string
}

variable "hostname" {
  description = "DNS hostname; defaults to `name`."
  type        = string
  default     = ""
}

variable "fleetd_url" {
  description = "Base URL of the control plane used for certificate renewal."
  type        = string
  default     = "https://fleetd.fleet.internal:8443"
}

variable "enroll_url" {
  description = "Base URL of the token-gated enrollment listener."
  type        = string
  default     = "https://fleetd.fleet.internal:8444"
}

variable "bootstrap_token" {
  description = "Single-use bootstrap token issued by `fleetctl token create`."
  type        = string
  sensitive   = true
}

variable "trust_bundle" {
  description = "PEM trust bundle placed at /etc/fleet-agent/trust-bundle.pem."
  type        = string
  sensitive   = true
}

variable "distro" {
  description = "Distribution simulated for attestation policy (ubuntu or fedora)."
  type        = string
  default     = "ubuntu"

  validation {
    condition     = contains(["ubuntu", "fedora"], var.distro)
    error_message = "distro must be ubuntu or fedora."
  }
}

variable "ntp_server" {
  description = "Site NTP server."
  type        = string
  default     = "ntp.fleet.internal"
}

variable "key_name" {
  description = "Optional EC2 key pair for break-glass SSH."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
