data "aws_rds_reserved_instance_offering" "example" {
  db_instance_class = "db.m7g.large"
}

resource "aws_rds_reserved_instance" "example" {
  offering_id    = data.aws_rds_reserved_instance_offering.example.offering_id
  instance_count = 1
}

resource "aws_db_instance" "example" {
  instance_class = aws_rds_reserved_instance.example.db_instance_class
  tags           = aws_rds_reserved_instance.example.tags.Name
}
