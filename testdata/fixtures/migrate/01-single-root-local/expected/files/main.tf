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
