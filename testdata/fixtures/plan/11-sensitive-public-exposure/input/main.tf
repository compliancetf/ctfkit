# Class 1, public exposure. Two findings: the public access block on
# public_site is switched off, and a bucket policy grants any principal read
# access with no condition.
resource "aws_s3_bucket_public_access_block" "public_site" {
  bucket = "bobthecorp-public-site"

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_site" {
  bucket = "bobthecorp-public-site"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::bobthecorp-public-site/*"
    }]
  })
}

# Clean counterpart: an identical public access block left untouched. It is a
# no-op in the plan and must produce no finding.
resource "aws_s3_bucket_public_access_block" "private_data" {
  bucket = "bobthecorp-private-data"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
