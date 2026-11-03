module "s3_bucket_notification" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "~> 5.0"

  bucket = module.naming.bucket
}

module "naming" {
  source = "./modules/naming"
}
