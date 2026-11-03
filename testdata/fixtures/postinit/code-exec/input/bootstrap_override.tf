# An override file replaces the provisioners of the block it overrides, so a
# provisioner here runs even though main.tf declares the resource.
resource "terraform_data" "bootstrap" {
  provisioner "file" {
    source      = "CANARY-codeexec-override-source"
    destination = "/tmp/bootstrap"
  }
}
