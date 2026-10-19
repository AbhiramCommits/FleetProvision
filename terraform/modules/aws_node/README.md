# aws_node

Creates one EC2 node from a Packer golden image, with an instance profile that
grants only SSM (no workload AWS credentials), IMDSv2 required, an encrypted
gp3 root volume, and cloud-init that enrolls the node into the fleet.

The cloud-init template lives at `provisioning/cloud-init/node.yaml.tftpl`.
It writes the trust bundle, a bootstrap token file (mode 0600), chrony and
sshd hardening snippets, then runs `fleet-agent enroll` and enables the
renewal timer.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Node identity |
| `ami` | string | required | Packer-built AMI |
| `instance_type` | string | `t3.medium` | EC2 size |
| `subnet_id` | string | required | Private subnet |
| `security_group_ids` | list(string) | required | Security groups |
| `site` | string | required | Fleet site |
| `hostname` | string | `""` | Defaults to `name` |
| `fleetd_url` | string | `https://fleetd.fleet.internal:8443` | Renewal URL |
| `enroll_url` | string | `https://fleetd.fleet.internal:8444` | Enrollment URL |
| `bootstrap_token` | string, sensitive | required | Single-use token |
| `trust_bundle` | string, sensitive | required | PEM CA bundle |
| `distro` | string | `ubuntu` | ubuntu or fedora |
| `ntp_server` | string | `ntp.fleet.internal` | Site NTP |
| `key_name` | string | `null` | Optional break-glass key |
| `tags` | map(string) | `{}` | Extra tags |

## Outputs

| Name | Description |
| --- | --- |
| `instance_id` | EC2 instance ID |
| `private_ip` | Private IPv4 address |
| `hostname` | Effective hostname |
| `iam_role_arn` | Node IAM role |
| `instance_profile_name` | Instance profile |
