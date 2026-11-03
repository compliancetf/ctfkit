module "bucket" {
  source  = "bobthecorp/s3-bucket/aws"
  version = "2.0.1"

  bucket = "bobthecorp-audit"
}
