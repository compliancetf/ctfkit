module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "my-bucket"
  acl    = "private"
}

module "vpc" {
  source  = "registry.terraform.io/hashicorp/aws/vpc"
  version = "~> 1.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"
}

# A raw git source: not a compliance.tf endpoint, and it carries no registry host at
# all, so it exercises a different branch of endpoint matching than the two above.
# Ported from the orphaned tests/ fixture tree before that tree was removed.
module "vpc_from_git" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git"

  name = "my-git-vpc"
  cidr = "10.0.0.0/16"
}
