module "s3_bucket" {
  source  = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "my-secure-bucket"
  acl    = "private"

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

module "vpc" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_dns_hostnames = true
}

module "local_helper" {
  source = "./modules/helper"

  config = {
    environment = "production"
  }
}

# A bare resource block. With no `allowed_resources` configured the resource-type
# validator is disabled, so this must still pass; testdata/fail/disallowed_resource.tf
# is the same shape under a config that does set an allowlist.
resource "aws_s3_bucket_versioning" "example" {
  bucket = module.s3_bucket.s3_bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}
