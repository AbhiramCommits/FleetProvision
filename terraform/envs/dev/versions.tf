terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state is intentionally disabled for local/offline validation.
  # For a real deployment, uncomment this block and initialize with:
  #   terraform init -backend-config=backend.hcl
  #
  # backend "s3" {
  #   bucket         = "fleetprovision-terraform-state"
  #   key            = "envs/dev/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "fleetprovision-terraform-locks"
  # }
}
