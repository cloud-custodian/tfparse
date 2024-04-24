module "bucket" {
  source = "./module/bucket"
  #passed into module
  default_tags = local.default_tags
}

#large map of tags for different categories
variable "tags" {
 type = map
 default = {
    tags_base = {
      tag_important_tag   = "APPID-000000000"
    }
  }
}

#they invoke four different modules like this for different groups of tags. Picks out expected tag values from map
module "tags_base" {
  source                    = "./module/tags/base"
  tags_base                 = var.tags["tags_base"]
}

#this is usually merge statement of all the different tag module outputs. Single module for test
locals {
  default_tags = module.tags_base.tags
}