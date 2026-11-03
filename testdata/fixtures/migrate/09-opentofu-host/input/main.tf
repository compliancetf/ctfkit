terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "registry.opentofu.org/hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "local" {}
}

provider "aws" {
  region = "eu-west-1"
}

module "dns" {
  source = "./modules/dns"

  zone = "bobthecorp.example"
}
