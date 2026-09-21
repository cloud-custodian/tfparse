variable "names" {
  default = ["a"]
}

module "labels" {
  for_each = toset(var.names)
  source   = "./labels"
  name     = each.key
}

module "child" {
  for_each = toset(var.names)
  source   = "./child"
  keys = {
    storage = {
      labels = module.labels[each.key].out
    }
  }
}
