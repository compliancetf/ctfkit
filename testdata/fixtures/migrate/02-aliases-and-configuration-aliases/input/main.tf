terraform {
  required_version = ">= 1.5"

  required_providers {
    # Primary account, two regions.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # Production account under its own local name.
    awsprod = { source = "hashicorp/aws" }
  }

  backend "local" {}
}

provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  alias  = "west"
  region = "eu-west-2"
}

provider "awsprod" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}

resource "aws_s3_bucket" "prod_logs" {
  provider = awsprod
  bucket   = "bobthecorp-prod-logs"
}

module "replica" {
  source = "./modules/replica"

  providers = {
    aws      = aws
    aws.west = aws.west
  }
}
