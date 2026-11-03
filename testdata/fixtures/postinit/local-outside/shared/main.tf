# A blueprint beside the configuration directory, which the configuration
# calls as ../shared. The source is explicit and terraform runs it, so report
# and scan both read this directory and report the provisioner below.
module "bucket" {
  source  = "bobthecorp.compliance.tf/terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "~> 5.0"

  bucket = "bobthecorp-fixture-shared"
}

check "shared" {
  data "external" "probe" {
    program = ["CANARY-codeexec-outside-check-program"]
  }

  assert {
    condition     = true
    error_message = "unreachable"
  }
}

resource "terraform_data" "outside" {
  provisioner "local-exec" {
    command = "echo CANARY-codeexec-outside-command"
  }
}
