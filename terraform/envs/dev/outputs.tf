output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnet_ids" {
  value = module.vpc.private_subnet_ids
}

output "fleetd_security_group_id" {
  value = module.vpc.fleetd_security_group_id
}

output "node_instance_ids" {
  value = module.node[*].instance_id
}

output "node_private_ips" {
  value = module.node[*].private_ip
}
