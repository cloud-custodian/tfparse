module "notify_slack_saas" {
  source  = "terraform-aws-modules/notify-slack/aws"
  version = "~> 5.3.0"

  iam_role_name_prefix = var.prefix
  sns_topic_name       = "slack-alert-saas"
  slack_webhook_url    = "https://localhost"
  slack_channel        = "feed-ops-saas"
  slack_username       = "${data.aws_caller_identity.current.account_id}-sns"
  lambda_function_name = "notify_slack_saas"
  sns_topic_kms_key_id = local.sns_kms_key_arn

  tags = merge(
    local.tags,
    {
      Source   = "shared-infra/deploy/operations",
      TFModule = "terraform-aws-modules/notify-slack/aws"
    },
  )
}

module "notify_slack_qa" {
  source  = "terraform-aws-modules/notify-slack/aws"
  version = "~> 5.1.0"

  iam_role_name_prefix = var.prefix
  sns_topic_name       = "slack-alert-qa"
  slack_webhook_url    = "https://localhost"
  slack_channel        = "feed-ops-qa"
  slack_username       = "${data.aws_caller_identity.current.account_id}-sns"
  lambda_function_name = "notify_slack_qa"
  sns_topic_kms_key_id = local.sns_kms_key_arn

  tags = merge(
    local.tags,
    {
      Source   = "shared-infra/deploy/operations",
      TFModule = "terraform-aws-modules/notify-slack/aws"
    },
  )
}
