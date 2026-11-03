module "s3_bucket" {
  source = "https://soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?version=5.16.1&disable=s3_bucket_versioning_enabled"

bucket = "bobthecorp-disabled"

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
        bucket = "arn:aws:s3:::bobthecorp-disabled-replica"
      }
    }]
  }
}
