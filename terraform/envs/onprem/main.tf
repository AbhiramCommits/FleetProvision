module "rack" {
  source = "../../modules/onprem_rack"

  name        = var.rack_name
  bridge_name = var.bridge_name
  node_count  = var.node_count
  image_path  = var.image_path
  tags = {
    fleet_site = "onprem"
    rack       = var.rack_name
  }
}
