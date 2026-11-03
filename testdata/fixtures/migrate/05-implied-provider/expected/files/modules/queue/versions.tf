terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = ">= 6.0.0"
    }
  }
}
