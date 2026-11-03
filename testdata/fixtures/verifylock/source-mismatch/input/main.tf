terraform {
  backend "local" {}
  required_providers {
    aws = {
      version = "~> 6.10"
    }
  }
}

module "net" {
  source = "./modules/net"
}
