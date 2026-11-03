# Test lock file: gate plan runs verify-lock on the root before terraform.

provider "registry.compliance.tf/compliancetf/aws" {
  version     = "2.0.0"
  constraints = "~> 2.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "zh:1111111111111111111111111111111111111111111111111111111111111111",
  ]
}
