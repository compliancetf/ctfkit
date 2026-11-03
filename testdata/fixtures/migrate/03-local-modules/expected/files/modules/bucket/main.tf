terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = ">= 5.0"
    }
  }
}

variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}

module "logging" {
  source = "../logging"

  bucket = aws_s3_bucket.this.id
}
