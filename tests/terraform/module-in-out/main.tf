variable "tags" {
  type = map(any)
  default = {
    env = "dev"
    app = "weather"
  }
}


module "tags_base" {
  source = "./module/tags"
  tags_base = var.tags
}


locals {
  default_tags = module.tags_base.tags
}


module "bucket" {
  source = "./module/bucket"
  default_tags = local.default_tags
}
