terraform {
  backend "local" {}
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
