terraform {
  required_version = ">= 1.6.0"

  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8.0"
    }
  }

  # Uncomment for remote state:
  # backend "s3" {
  #   bucket         = "fleetprovision-terraform-state"
  #   key            = "envs/onprem/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "fleetprovision-terraform-locks"
  # }
}
