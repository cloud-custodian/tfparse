provider "aws" {
  access_key = "c7n"
  secret_key = "left"
  region     = "us-east-1"

  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs#s3_use_path_style
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    s3 = "http://localhost:4566"
  }
}

resource "aws_s3_bucket" "aes-encrypted-bucket" {
  bucket = "my-aes-encrypted-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aes-encrypted-configuration" {
  bucket = aws_s3_bucket.aes-encrypted-bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "kms-encrypted-bucket" {
  bucket = "my-kms-encrypted-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kms-encrypted-configuration" {
  bucket = aws_s3_bucket.kms-encrypted-bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket" "sample-bucket" {
  bucket = "sample-bucket"
}

resource "aws_s3_bucket" "log-bucket" {
  bucket = "log-bucket"
}

resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.sample-bucket.id
  target_bucket = aws_s3_bucket.log-bucket.id
  target_prefix = "log/"
}
