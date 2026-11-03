removed {
  from = terraform_data.legacy

  lifecycle {
    destroy = true
  }

  provisioner "local-exec" {
    when    = destroy
    command = "echo CANARY-codeexec-removed-command"
  }
}
