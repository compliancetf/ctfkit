terraform {
  backend "s3" {
    bucket = "bobthecorp-terraform-state"
    key    = "fixture/terraform.tfstate"
    region = "eu-west-1"
  }
}
