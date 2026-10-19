# aws_vpc

Creates a two-AZ VPC for FleetProvision: two public subnets (one per AZ), two
private subnets, an internet gateway, an optional single NAT gateway, and two
security groups.

## Security groups

* `fleetd` — TCP 8443 from the VPC CIDR and the bastion CIDR; SSH 22 from the
  bastion CIDR only. No other inbound traffic is permitted.
* Egress is unrestricted so nodes can reach package mirrors, the OIDC issuer,
  and an external fleetd if you deploy it outside the VPC.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Prefix for every resource name |
| `cidr_block` | string | `10.42.0.0/16` | VPC CIDR |
| `availability_zones` | list(string) | required | Exactly two AZs |
| `public_subnet_cidrs` | list(string) | `10.42.10.0/24`, `10.42.20.0/24` | Public subnet CIDRs |
| `private_subnet_cidrs` | list(string) | `10.42.110.0/24`, `10.42.120.0/24` | Private subnet CIDRs |
| `enable_nat` | bool | `true` | Create a NAT gateway |
| `bastion_cidr` | string | `203.0.113.0/24` | Allowed SSH/fleetd source |
| `fleetd_port` | number | `8443` | mTLS port |
| `tags` | map(string) | `{}` | Extra tags |

## Outputs

| Name | Description |
| --- | --- |
| `vpc_id` | VPC ID |
| `public_subnet_ids` | Two public subnet IDs |
| `private_subnet_ids` | Two private subnet IDs |
| `fleetd_security_group_id` | Security group to attach to the control plane / nodes |
| `nat_gateway_id` | NAT gateway ID, or `null` when `enable_nat = false` |
