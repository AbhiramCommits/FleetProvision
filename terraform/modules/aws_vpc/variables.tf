variable "name" {
  description = "Prefix for all resource names."
  type        = string
}

variable "cidr_block" {
  description = "VPC IPv4 CIDR."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Exactly two availability zones for the public and private subnets."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) == 2
    error_message = "Provide exactly two availability zones."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDRs for the two public subnets."
  type        = list(string)
  default     = ["10.42.10.0/24", "10.42.20.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) == 2
    error_message = "Provide exactly two public subnet CIDRs."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDRs for the two private subnets."
  type        = list(string)
  default     = ["10.42.110.0/24", "10.42.120.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) == 2
    error_message = "Provide exactly two private subnet CIDRs."
  }
}

variable "enable_nat" {
  description = "Create a NAT gateway so private nodes can reach fleetd and package mirrors."
  type        = bool
  default     = true
}

variable "bastion_cidr" {
  description = "CIDR allowed to reach SSH and fleetd for break-glass access."
  type        = string
  default     = "203.0.113.0/24"
}

variable "fleetd_port" {
  description = "mTLS port exposed by the control plane."
  type        = number
  default     = 8443
}

variable "tags" {
  description = "Additional tags applied to every resource."
  type        = map(string)
  default     = {}
}
