module "labels" {
  source = "./labels"
  name   = "a"
}

locals {
  keys = {
    storage = {
      labels = module.labels.out
    }
  }
}

resource "google_storage_bucket" "x" {
  for_each = local.keys
  name     = "static-name-${each.key}"
  location = "US"
  labels   = each.value.labels
}
