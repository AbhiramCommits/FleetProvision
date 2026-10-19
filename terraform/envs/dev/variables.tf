variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "aws_access_key" {
  description = "Access key. Use dummy values for offline plan; use an SSO profile in real deployments."
  type        = string
  default     = "AKIAIOSFODNN7EXAMPLE"
}

variable "aws_secret_key" {
  description = "Secret key. Dummy value for offline plan."
  type        = string
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  sensitive   = true
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "dev"
}

variable "site" {
  description = "Fleet site label."
  type        = string
  default     = "aws-dev"
}

variable "availability_zones" {
  description = "Two AZs for the VPC."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "enable_nat" {
  description = "Create a NAT gateway (costs money)."
  type        = bool
  default     = true
}

variable "bastion_cidr" {
  description = "Operator/bastion CIDR."
  type        = string
  default     = "203.0.113.0/24"
}

variable "node_ami" {
  description = "Packer-built Ubuntu AMI."
  type        = string
  default     = "ami-0123456789abcdef0"
}

variable "node_instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.medium"
}

variable "node_count" {
  description = "Number of EC2 nodes."
  type        = number
  default     = 2

  validation {
    condition     = var.node_count >= 1 && var.node_count <= 10
    error_message = "node_count must be between 1 and 10."
  }
}

variable "fleetd_url" {
  description = "Control plane mTLS URL."
  type        = string
  default     = "https://fleetd.fleet.internal:8443"
}

variable "enroll_url" {
  description = "Control plane enrollment URL."
  type        = string
  default     = "https://fleetd.fleet.internal:8444"
}

variable "bootstrap_token" {
  description = "Bootstrap token for the dev nodes."
  type        = string
  default     = "dev-bootstrap-token"
  sensitive   = true
}

variable "trust_bundle" {
  description = "PEM trust bundle injected into cloud-init."
  type        = string
  default     = "-----BEGIN CERTIFICATE-----\nDEV-ONLY-PLAN-BUNDLE\n-----END CERTIFICATE-----\n"
  sensitive   = true
}
