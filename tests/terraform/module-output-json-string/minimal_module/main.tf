variable "container_name" {
  type = string
}

variable "map_environment" {
  type    = map(string)
  default = null
}

locals {
  # This pattern triggers UnknownVal: for loop inside ternary
  final_environment_vars = var.map_environment != null ? [
    for k, v in var.map_environment : {
      name  = k
      value = v
    }
  ] : null

  container_definition = {
    name        = var.container_name
    environment = local.final_environment_vars
  }

  container_definition_without_null = {
    for k, v in local.container_definition :
    k => v
    if v != null
  }

  final_container_definition = merge(local.container_definition_without_null, {})

  json_map = jsonencode(local.final_container_definition)
}

output "json_map_encoded_list" {
  value = "[${local.json_map}]"
}
