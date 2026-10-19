#version=F40
# FleetProvision Fedora Server 40 unattended Kickstart.
# Served over HTTP by the provisioning simulator or the site TFTP/HTTP pair.
text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --device=link --activate
rootpw --lock
user --name=fedora --groups=wheel --plaintext --password=fedora
selinux --enforcing
firewall --enabled --service=ssh
services --enabled=sshd,chronyd,qemu-guest-agent
bootloader --location=mbr --boot-drive=vda
zerombr
clearpart --all --initlabel --drives=vda
autopart --type=plain --fstype=xfs
reboot

%packages
@^server-product-environment
chrony
qemu-guest-agent
curl
jq
policycoreutils-python-utils
%end

%post --erroronfail
set -euxo pipefail
# Pin the fleet CA bundle at image build time. The real bundle is injected by
# the Ansible role; this path must exist before the image is sealed.
install -d -m 0755 /etc/fleet-agent /var/lib/fleet-agent
chmod 0700 /var/lib/fleet-agent
# Boot-time enrollment uses the per-node token written by cloud-init/user-data.
# The token is fetched over HTTPS with the pinned bundle, never over plaintext.
systemctl enable sshd chronyd qemu-guest-agent
systemctl disable firewalld || true
%end
