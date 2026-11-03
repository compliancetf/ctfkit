# The module a run block of main.tftest.hcl installs: test scaffolding, keyed
# test.main.setup, never part of the configuration under analysis.
resource "terraform_data" "setup" {
  provisioner "local-exec" {
    command = "echo CANARY-layout-harness"
  }
}
