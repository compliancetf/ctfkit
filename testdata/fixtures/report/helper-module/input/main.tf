module "s3_bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = module.naming.bucket_name
}

module "naming" {
  source = "./modules/naming"

  prefix = "bobthecorp-helper-module"
}
