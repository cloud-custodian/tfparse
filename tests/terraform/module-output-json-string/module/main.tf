variable "name" {
  type        = string
  description = "Container name"
}

variable "image" {
  type        = string
  description = "Container image"
}

locals {
  container_definition = {
    name      = var.name
    image     = var.image
    essential = true
    portMappings = [
      {
        containerPort = 80
        protocol      = "tcp"
      }
    ]
  }

  # This simulates what simple modules do - direct jsonencode
  json_map = jsonencode(local.container_definition)
}

output "json_encoded_list" {
  description = "JSON string encoded list of container definitions"
  value       = "[${local.json_map}]"
}

output "json_map_object" {
  description = "Container definition as an object"
  value       = local.container_definition
}
