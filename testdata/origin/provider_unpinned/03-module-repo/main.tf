resource "aws_s3_bucket" "this" {
  bucket_prefix = "bobthecorp-"
}

module "sub" {
  source = "./modules/sub"
}
