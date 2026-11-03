resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-logs"
}

resource "aws_sqs_queue" "jobs" {
  name = "bobthecorp-jobs"
}

module "store" {
  source = "./modules/store"
}

module "bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"
}
