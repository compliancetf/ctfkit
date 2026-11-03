# Test lock file: the versions a gate sign verdict binds; the wrapper entry
# carries a zh: hash, so verify-lock in gate plan and apply passes.

provider "registry.compliance.tf/compliancetf/aws" {
  version     = "2.0.0"
  constraints = "~> 2.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "zh:1111111111111111111111111111111111111111111111111111111111111111",
  ]
}

provider "registry.terraform.io/hashicorp/aws" {
  version     = "6.20.0"
  constraints = "6.20.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  ]
}
