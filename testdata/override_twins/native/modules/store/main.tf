resource "aws_s3_bucket" "this" {
  bucket_prefix = "bobthecorp-store-"
}

resource "aws_iam_role" "this" {
  name = "bobthecorp-store"
}
