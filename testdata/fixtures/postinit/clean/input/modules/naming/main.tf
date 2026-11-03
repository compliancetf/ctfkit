locals {
  bucket = "bobthecorp-fixture-logs"
}

output "bucket" {
  value = local.bucket
}
