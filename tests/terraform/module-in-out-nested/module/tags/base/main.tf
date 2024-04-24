
variable "tags_base" {
  type = map
}


variable "additional_tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = {
    "important-tag"     = var.tags_base["tag_important_tag"]
  }
}

output "tags" {
  value = merge(local.tags, var.additional_tags)
}
