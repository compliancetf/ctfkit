# No compliance.tf module anywhere: scan still reports the code this
# configuration would run, from the root and from its local module.
resource "terraform_data" "bootstrap" {
  provisioner "local-exec" {
    command = "echo CANARY-exec-pre-plan-command"
  }
}

module "hook" {
  source = "./modules/hook"
}

# A data source scoped to a check block is read at plan like any other.
check "health" {
  data "external" "probe" {
    program = ["CANARY-exec-pre-plan-check-program"]
  }

  assert {
    condition     = true
    error_message = "unreachable"
  }
}
