locals {
  hostname = var.hostname != "" ? var.hostname : var.name
  tags = merge(var.tags, {
    Name        = var.name
    ManagedBy   = "terraform"
    Module      = "aws_node"
    fleet_site  = var.site
    fleet_role  = "worker"
    fleet_image = "packer-golden"
  })
  trust_bundle_b64    = base64encode(var.trust_bundle)
  bootstrap_token_b64 = base64encode(var.bootstrap_token)
  enroll_env_b64 = base64encode(join("\n", [
    "FLEET_ENROLL_URL=${var.enroll_url}",
    "FLEET_NODE_ID=${var.name}",
    "FLEET_SITE=${var.site}",
    "FLEET_BOOTSTRAP_TOKEN=${var.bootstrap_token}",
    "",
  ]))
}

data "aws_partition" "current" {}

resource "aws_iam_role" "node" {
  name_prefix = "${var.name}-fleet-node-"
  description = "FleetProvision node role: SSM only, no AWS API credentials for workloads"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "node" {
  name_prefix = "${var.name}-fleet-node-"
  role        = aws_iam_role.node.name
  tags        = local.tags
}

resource "aws_instance" "node" {
  ami                    = var.ami
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.security_group_ids
  iam_instance_profile   = aws_iam_instance_profile.node.name
  key_name               = var.key_name
  user_data = templatefile("${path.module}/../../../provisioning/cloud-init/node.yaml.tftpl", {
    hostname            = local.hostname
    node_id             = var.name
    site                = var.site
    enroll_url          = var.enroll_url
    distro              = var.distro
    ntp_server          = var.ntp_server
    trust_bundle_b64    = local.trust_bundle_b64
    bootstrap_token_b64 = local.bootstrap_token_b64
    enroll_env_b64      = local.enroll_env_b64
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 40
    encrypted             = true
    delete_on_termination = true
  }

  tags = local.tags
}
