variable "keys" {}

resource "google_storage_bucket" "x" {
  for_each = var.keys
  name     = "static-name-${each.key}"
  location = "US"
  labels   = each.value.labels
}
