locals {
  current_month = formatdate("M", plantimestamp())
  last_month    = local.current_month == "1" ? "12" : tostring(tonumber(local.current_month) - 1)
}

resource "terraform_data" "dummy" {
      for_each = toset([local.last_month, local.current_month])
}
