module "s3_bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-blueprint-data"
}

resource "aws_sns_topic" "bucket_events" {
  name = "bobthecorp-blueprint-events"
}

resource "aws_sqs_queue" "bucket_events" {
  name = "bobthecorp-blueprint-events"
}

resource "aws_iam_role" "replication" {
  name               = "bobthecorp-blueprint-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
}

data "aws_iam_policy_document" "replication_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}
