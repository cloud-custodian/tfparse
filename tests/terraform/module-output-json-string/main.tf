# Variables without defaults - makes them unresolvable at static analysis time
variable "root_task_name" {
  type = string
  # NO DEFAULT - unresolvable
}

variable "root_image" {
  type = string
  # NO DEFAULT - unresolvable
}

# Direct module usage - this works fine
module "container_direct" {
  source = "./module"
  name   = "direct-container"
  image  = "nginx:latest"
}

resource "aws_ecs_task_definition" "direct" {
  family                   = "direct-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  # Direct module reference - this should work
  container_definitions = module.container_direct.json_encoded_list
}

# Nested module usage - this reproduces the issue
# Pass unresolvable variables to the wrapper module
module "task_wrapper" {
  source    = "./modules/task_wrapper"
  task_name = var.root_task_name  # Unknown!
  image     = var.root_image      # Unknown!
}
