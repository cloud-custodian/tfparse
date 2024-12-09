locals {
  map = {
    default = "DEFAULT"
    other   = "OTHER"
  }
  value = local.map[terraform.workspace]
}

output "workspace" {
  value = terraform.workspace
}

output "value" {
  value = local.value
}
