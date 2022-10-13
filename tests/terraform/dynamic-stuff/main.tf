variable "environment_variables" {
  default = {
    "hello" : "world"
  }
}

variable "ephemeral_storage_size" {
  default = 100
}

resource "aws_lambda_function" "this" {
  /* ephemeral_storage is not supported in gov-cloud region, so it should be set to `null` */
  dynamic "ephemeral_storage" {
    for_each = [true]

    content {
      size = var.ephemeral_storage_size
    }
  }

  dynamic "image_config" {
    for_each = [true]
    content {
      entry_point       = var.image_config_entry_point
      command           = var.image_config_command
      working_directory = var.image_config_working_directory
    }
  }

  dynamic "environment" {
    for_each = length(keys(var.environment_variables)) == 0 ? [] : [true]
    content {
      variables = var.environment_variables
    }
  }
}
