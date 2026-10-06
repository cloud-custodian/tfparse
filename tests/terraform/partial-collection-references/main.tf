resource "aws_iam_role" "app" {
  name = "app"
}

locals {
  group = "arn:aws:iam::123456789012:group/admins"
}

module "policy" {
  source = "./policy"
  # One element is known now, the other only after apply.
  principals = [local.group, aws_iam_role.app.unique_id]
  grants = {
    reader = aws_iam_role.app.unique_id
    owner  = local.group
  }
}
