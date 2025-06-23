module "bucket" {
  source      = "./modules/nonpublic_bucket"
  bucket_name = "module-bucket"
}

resource "aws_s3_bucket" "outside_module" {
  bucket = "non-module-bucket"
}

resource "aws_s3_bucket_public_access_block" "outside_module" {
  bucket = aws_s3_bucket.outside_module.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
