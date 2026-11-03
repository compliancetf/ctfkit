terraform {
  required_providers {
    aws = {
      source  = "registry.compliance.tf/compliancetf/aws"
      version = ">= 5.0"
    } # legacy string form
  }
}

variable "zone" {
  type = string
}

resource "aws_route53_zone" "this" {
  name = var.zone
}
