locals {
  current_month = 6
  last_month    = 5
}

resource "terraform_data" "dummy" {
      for_each = toset([local.last_month, local.current_month])
}
