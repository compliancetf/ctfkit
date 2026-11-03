terraform {
  backend "local" {}
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}
