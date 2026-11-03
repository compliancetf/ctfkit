# A child of ../shared, outside the configuration directory: read because the
# source that leads here is explicit.
resource "terraform_data" "sub" {
  provisioner "local-exec" {
    command = "echo CANARY-layout-shared-sub"
  }
}
