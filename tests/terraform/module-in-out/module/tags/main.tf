
variable "tags_base" {
  type    = map(any)
  default = {}
}

variable "additional_tags" {
  type    = map(string)
  default = {}
}


locals {
  tags = {
    "app-id" = "static"
  }

}

output "tags" {
  value = merge(local.tags, var.tags_base, var.additional_tags)
}
