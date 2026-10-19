module "vpc" {
  source = "../../modules/aws_vpc"

  name               = "fleet-${var.environment}"
  cidr_block         = "10.42.0.0/16"
  availability_zones = var.availability_zones
  enable_nat         = var.enable_nat
  bastion_cidr       = var.bastion_cidr
  fleetd_port        = 8443
  tags = {
    Site = var.site
  }
}

module "node" {
  source = "../../modules/aws_node"
  count  = var.node_count

  name               = "aws-${var.environment}-node-${format("%02d", count.index + 1)}"
  ami                = var.node_ami
  instance_type      = var.node_instance_type
  subnet_id          = module.vpc.private_subnet_ids[count.index % 2]
  security_group_ids = [module.vpc.fleetd_security_group_id]
  site               = var.site
  fleetd_url         = var.fleetd_url
  enroll_url         = var.enroll_url
  bootstrap_token    = var.bootstrap_token
  trust_bundle       = var.trust_bundle
  distro             = "ubuntu"
  tags = {
    Site = var.site
    Role = "worker"
  }
}
