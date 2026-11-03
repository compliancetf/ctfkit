module "archive" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-example-archive"

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
    target_bucket = "bobthecorp-example-access-logs"
    target_prefix = "archive/"
  }

  lifecycle_rule = [{
    id     = "expire-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration = {
      days = 300
    }
  }]

  replication_configuration = {
    role = "arn:aws:iam::111111111111:role/bobthecorp-example-replication"

    rules = [{
      id     = "replicate-all"
      status = "Enabled"

      destination = {
        bucket = "arn:aws:s3:::bobthecorp-example-archive-replica"
      }
    }]
  }
}

module "data" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-example-data"

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
    target_bucket = "bobthecorp-example-access-logs"
    target_prefix = "data/"
  }

  lifecycle_rule = [{
    id     = "expire-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration = {
      days = 300
    }
  }]

  replication_configuration = {
    role = "arn:aws:iam::111111111111:role/bobthecorp-example-replication"

    rules = [{
      id     = "replicate-all"
      status = "Enabled"

      destination = {
        bucket = "arn:aws:s3:::bobthecorp-example-data-replica"
      }
    }]
  }
}

module "artifacts" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "~> 5.0"

  bucket = "bobthecorp-example-artifacts"

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
    target_bucket = "bobthecorp-example-access-logs"
    target_prefix = "artifacts/"
  }

  lifecycle_rule = [{
    id     = "expire-noncurrent"
    status = "Enabled"

    noncurrent_version_expiration = {
      days = 300
    }
  }]

  replication_configuration = {
    role = "arn:aws:iam::111111111111:role/bobthecorp-example-replication"

    rules = [{
      id     = "replicate-all"
      status = "Enabled"

      destination = {
        bucket = "arn:aws:s3:::bobthecorp-example-artifacts-replica"
      }
    }]
  }
}
