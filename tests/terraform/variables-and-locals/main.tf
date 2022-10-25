locals {
  hello = "world"
  bool = true
  number = 3
  list = [1, 2, 3]
  list_count = length(local.list)
  object = {
    hello = "world"
  }
  complex = {
    list = [
      {index = 1},
      {index = 2},
      {index = 3},
    ]
  }
}

variable "has_default" {
  default = "the default"
}

variable "no_default" {
  type = string
}

variable "local_ref" {
  default = local.bool
}
