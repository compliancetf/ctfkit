module "s3_bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-delegated-data"
}

module "s3_bucket_notification" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "~> 5.0"

  bucket = "bobthecorp-delegated-data"
}

module "s3_account_public_access" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/account-public-access"
  version = "~> 5.0"
}
