provider "aws" {
  region = "eu-west-1"
}

module "a" {
  source = "../../modules/a"
}
