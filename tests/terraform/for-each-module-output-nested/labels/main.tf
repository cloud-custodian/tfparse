variable "name" {
  type = string
}

output "out" {
  value = {
    name   = var.name
    static = "x"
  }
}
