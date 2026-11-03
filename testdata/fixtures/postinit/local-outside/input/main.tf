module "s3_bucket_notification" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "~> 5.0"

  bucket = "bobthecorp-fixture-logs"
}

# A local module beside the configuration directory. Its source is explicit,
# so report and scan read it and report its provisioner.
module "shared" {
  source = "../shared"
}
