variable "task_name" {
  type = string
  # NO DEFAULT - makes it unresolvable at static analysis time
}

variable "image" {
  type = string
  # NO DEFAULT - makes it unresolvable at static analysis time
}

variable "environment_vars" {
  type    = map(string)
  default = {}
  # Has a default, but when overridden, makes things unresolvable
}

# Nested module - testing minimal complexity to trigger UnknownVal
module "container" {
  source          = "../../minimal_module"
  container_name  = var.task_name  # Unknown!
  container_image = var.image      # Unknown!
}

resource "aws_ecs_task_definition" "wrapped_task" {
  family                   = var.task_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"

  # This references a nested module output (cloudposse uses json_map_encoded_list)
  container_definitions = module.container.json_map_encoded_list
}

output "task_arn" {
  value = aws_ecs_task_definition.wrapped_task.arn
}
