terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = ">= 5.0"
    }
  }
}

variable "bucket" {
  type = string
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = var.bucket
  target_bucket = var.bucket
  target_prefix = "log/"
}
