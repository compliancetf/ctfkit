# A resource with no manifest makes ctf.coverage.manifest_missing quote this
# module's credentialed source, which must reach the finding redacted.
resource "terraform_data" "tools" {}
