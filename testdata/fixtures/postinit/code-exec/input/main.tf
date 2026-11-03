module "s3_bucket_notification" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "~> 5.0"

  bucket = "bobthecorp-fixture-logs"
}

# A remote module from outside the allowed endpoints. As a root call it is
# ctf.coverage.module_source's subject at scan time, not report's. It calls a
# public registry module, a credentialed git module and a local child of its
# own, and those nested calls are ctf.exec.module_endpoint's.
module "app" {
  source = "git::https://example.com/bobthecorp/app.git?ref=v1.2.0"
}

resource "terraform_data" "bootstrap" {
  provisioner "local-exec" {
    command = "echo CANARY-codeexec-root-command"
  }
}
