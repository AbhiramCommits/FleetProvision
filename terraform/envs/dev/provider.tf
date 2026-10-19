provider "aws" {
  region = var.aws_region

  # Offline validation: dummy credentials plus validation skips let
  # `terraform validate` and `terraform plan` run without an AWS account.
  access_key                  = var.aws_access_key
  secret_key                  = var.aws_secret_key
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true

  default_tags {
    tags = {
      Project   = "FleetProvision"
      ManagedBy = "terraform"
      Env       = var.environment
    }
  }
}
