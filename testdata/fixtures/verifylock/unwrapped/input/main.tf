terraform {
  backend "local" {}
  required_providers {
    google = {
      source  = "registry.compliance.tf/compliancetf/google"
      version = "~> 6.10"
    }
  }
}
