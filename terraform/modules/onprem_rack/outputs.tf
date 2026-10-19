output "domain_names" {
  value = libvirt_domain.node[*].name
}

output "mac_addresses" {
  value = local.macs
}

output "volume_ids" {
  value = libvirt_volume.node[*].id
}

output "pool_name" {
  value = libvirt_pool.images.name
}
