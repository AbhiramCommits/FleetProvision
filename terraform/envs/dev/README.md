# envs/dev

AWS development estate: one VPC (`modules/aws_vpc`) and N EC2 nodes
(`modules/aws_node`) built from a Packer golden image.

## Offline validation

The provider accepts dummy credentials and disables credential, account, and
metadata lookups, so this works with no AWS account:

```bash
terraform init -backend=false
terraform validate
terraform plan -var-file=dummy.tfvars
```

`dummy.tfvars` is not committed (see `.gitignore`); `make iac-validate`
generates it under `out/`.

## Real deployment

1. Build an AMI with `packer build packer/ubuntu`.
2. Export real credentials (or switch the provider to an SSO profile), set
   `node_ami`, and generate a trust bundle with `fleetctl ca show > bundle.pem`.
3. Issue a bootstrap token per node and set `bootstrap_token`.
4. `terraform init -backend-config=backend.hcl && terraform apply`.

**Warning:** applying this creates billable AWS resources, including a NAT
gateway and EC2 instances.
