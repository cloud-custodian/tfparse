locals {
  default_tags = {
    Environment = "sandbox"
  }
}

variable "tags" {
  default = {
    Environment = "sandbox"
  }
}

data "http" "example" {
  url = "https://checkpoint-api.hashicorp.com/v1/check/terraform"

  request_headers = {
    Accept = "application/json"
  }
}

resource "aws_db_parameter_group" "with_local" {
  name   = "with-local"
  family = "postgres16"

  tags = merge(
    local.default_tags,
    {
      ApplyTimeVal = data.http.example.status_code
    }
  )
}

resource "aws_db_parameter_group" "with_var" {
  name   = "with-vars"
  family = "postgres16"

  tags = merge(
    var.tags,
    {
      ApplyTimeVal = data.http.example.status_code
    }
  )
}

resource "aws_db_parameter_group" "untagged" {
  name   = "untagged"
  family = "postgres16"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "attribute_with_direct_reference" {
  permissions_boundary = data.aws_caller_identity.current.account_id
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "attribute_with_interpolated_reference" {
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/BoundaryPolicy"
    assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "attribute_not_present" {}
