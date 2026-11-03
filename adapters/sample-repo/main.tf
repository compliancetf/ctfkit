terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

# Served by the compliance.tf registry. After init its compliancetf-manifest.json sits in the module
# cache, and ctfkit reports every control this build enforces.
module "logs" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws"
  version = "5.16.1"

  bucket = "bobthecorp-ctfkit-sample-logs"

  # The bobthecorp build enforces these controls as input validation, so plan fails without them.
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
        bucket = "arn:aws:s3:::bobthecorp-ctfkit-sample-logs-replica"
      }
    }]
  }
}

# Declared straight in this root, so there is no manifest behind it. This is the finding the three
# screens in README.md all show: ctfkit reports the resource as not-evidence and names the module
# source that would cover it.
resource "aws_s3_bucket" "raw" {
  bucket = "bobthecorp-ctfkit-sample-raw"
}
