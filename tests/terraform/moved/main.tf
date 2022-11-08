resource "aws_instance" "b" {
  count = 2
}

moved {
  from = aws_instance.a
  to   = aws_instance.b
}
