resource "aws_s3_bucket" "this" {
  bucket_prefix = "bobthecorp-"
}

module "floating" {
  source = "git::https://github.com/bobthecorp/tf-s3.git?ref=main"
}
