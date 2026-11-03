terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = "~> 6.0"
    }
  }

  backend "local" {
    path = "state/bobthecorp.tfstate"
  }
}

provider "aws" {
  region = "eu-west-1"
}

module "bucket" {
  source = "./modules/bucket"

  name = "bobthecorp-data"
}
