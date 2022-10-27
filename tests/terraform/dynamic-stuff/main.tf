resource "some_resource" "this" {
  count = 2

  prop1 = "one"

  dynamic "loop_one" {
    for_each = [true, false, null]

    content {
      other = each.value
    }
  }

  static {
    name = "first"
  }

  prop2 = "two"

  dynamic "loop_two" {
    for_each = [1, 2, 3]

    content {
      other = each.value
    }
  }

  static {
    name = "second"
  }

  dynamic "loop_one" {
    for_each = ["aaa", "bbb", "ccc"]

    content {
      other = each.value
    }
  }

  prop3 = "end"
}
