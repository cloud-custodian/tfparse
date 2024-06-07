variable "empty_block" {
    // nothing here
}

output "empty_block" {
    value = var.empty_block
}


variable "default_only" {
    default = "huh"
}

output "default_only" {
    value = var.default_only
}


variable "quoted_type" {
    type = "string"
}

output "quoted_type" {
    value = var.quoted_type
}