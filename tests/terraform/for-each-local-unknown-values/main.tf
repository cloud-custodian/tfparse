resource "google_compute_subnetwork" "s" {
  name = "s"
}

locals {
  # The keys are known now; every value holds an attribute known only after apply.
  nodes = {
    a = { subnet = google_compute_subnetwork.s.self_link }
    b = { subnet = google_compute_subnetwork.s.self_link }
  }
}

module "node" {
  for_each = local.nodes
  source   = "./node"
  hostname = each.key
}
