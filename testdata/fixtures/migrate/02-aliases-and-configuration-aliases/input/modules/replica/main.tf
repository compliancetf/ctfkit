terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0"
      configuration_aliases = [aws.west]
    }
  }
}

resource "aws_s3_bucket" "replica" {
  provider = aws.west
  bucket   = "bobthecorp-replica"
}
