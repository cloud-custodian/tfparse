resource "aws_s3_bucket" "inside_module" {
  bucket = var.bucket_name
}

variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket_public_access_block" "inside_module" {
  bucket = aws_s3_bucket.inside_module.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
