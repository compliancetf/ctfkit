resource "aws_s3_bucket" "logs" {
  bucket = "bobthecorp-raw-logs"

  tags = {
    Environment = "dev"
    Owner       = "platform"
  }
}
