# Fixture for the bobthecorp test org.
#
# aws_s3_bucket is inside the allowlist used by the tests, aws_iam_role is
# outside it, so the same file is both the violation case and its control.

resource "aws_s3_bucket" "bobthecorp_logs" {
  bucket = "bobthecorp-logs"
}

resource "aws_iam_role" "bobthecorp_ci" {
  name               = "bobthecorp-ci"
  assume_role_policy = "{}"
}
