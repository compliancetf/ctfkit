terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = "~> 6.0"
    }
  }

  backend "local" {}
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}

resource "aws_s3_bucket" "assets" {
  bucket = "bobthecorp-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
