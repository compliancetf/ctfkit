module "s3_bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-missing-manifest-data"
}

module "replication_role" {
  source = "./modules/replication_role"

  name = "bobthecorp-missing-manifest-replication"
}
