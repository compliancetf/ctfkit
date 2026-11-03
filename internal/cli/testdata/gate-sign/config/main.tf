terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = "~> 2.0"
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}
