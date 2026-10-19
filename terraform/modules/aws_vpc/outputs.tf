output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "fleetd_security_group_id" {
  value = aws_security_group.fleetd.id
}

output "nat_gateway_id" {
  value = var.enable_nat ? aws_nat_gateway.this[0].id : null
}
