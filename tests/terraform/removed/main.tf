removed {
  from = aws_instance.a

  lifecycle {
    destroy = false
  }
}
