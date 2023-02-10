module "test" {
  source = "../module"
  input  = "testing"
}

output "root-output" {
  value = "hello-world"
}
