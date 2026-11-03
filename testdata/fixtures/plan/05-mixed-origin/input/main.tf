module "s3_bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

bucket = "bobthecorp-mixed"

  versioning = {
    enabled = "Enabled"
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "arn:aws:kms:eu-west-1:111111111111:key/11111111-1111-1111-1111-111111111111"
      }
    }
  }

  logging = {
    target_bucket = "bobthecorp-access-logs"
    target_prefix = "s3/"
  }

  lifecycle_rule = [{
    id     = "expire-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration = {
      days = 300
    }
  }]

  replication_configuration = {
    role = "arn:aws:iam::111111111111:role/bobthecorp-replication"

    rules = [{
      id     = "replicate-all"
      status = "Enabled"

      destination = {
        bucket = "arn:aws:s3:::bobthecorp-mixed-replica"
      }
    }]
  }
}

module "iam_policy" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-policy"
  version = "~> 6.0"

  name   = "bobthecorp-mixed-readonly"
  policy = data.aws_iam_policy_document.readonly.json
}

data "aws_iam_policy_document" "readonly" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bobthecorp-mixed/*"]
  }
}

resource "aws_sqs_queue" "events" {
  name = "bobthecorp-mixed-events"
}
