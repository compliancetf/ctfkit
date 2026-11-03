# Class 2, wildcard IAM. All four policies are created in this plan.

# Error: every action on every resource, no condition.
resource "aws_iam_policy" "admin" {
  name = "bobthecorp-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Warning: a service-wide action wildcard on every resource, no condition.
resource "aws_iam_policy" "s3_admin" {
  name = "bobthecorp-s3-admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

# No finding: a Deny statement never fires, even with both wildcards.
resource "aws_iam_policy" "deny_all" {
  name = "bobthecorp-deny-all"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Clean counterpart: named actions on a named resource.
resource "aws_iam_policy" "scoped_read" {
  name = "bobthecorp-scoped-read"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::bobthecorp-reports", "arn:aws:s3:::bobthecorp-reports/*"]
    }]
  })
}
