resource "aws_s3_bucket" "bucket_module" {
  tags = var.default_tags
}

variable "default_tags" {
  type = map(string)
}
