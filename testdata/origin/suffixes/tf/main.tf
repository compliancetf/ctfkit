terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_instance" "web" {
  instance_type = "t3.micro"
}

module "branch" {
  source = "git::https://github.com/bobthecorp/tf-s3.git?ref=main"
}

module "open" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.0"
}
