variable "prefix" {
  type = string
}

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "${var.prefix}-${data.aws_caller_identity.current.account_id}"
}

output "bucket_name" {
  value = local.bucket_name
}
