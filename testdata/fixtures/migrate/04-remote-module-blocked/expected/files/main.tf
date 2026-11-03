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

module "network" {
  source = "git::https://git.bobthecorp.example/infra/terraform-aws-network.git?ref=v1.4.0"

  name = "bobthecorp-prod"
}

module "audit" {
  source = "./modules/audit"
}
