# A child of a root module call named "test": configuration, not a test
# harness module, so its provisioner must be reported.
resource "terraform_data" "hook" {
  provisioner "local-exec" {
    command = "echo CANARY-layout-test-hook"
  }
}
