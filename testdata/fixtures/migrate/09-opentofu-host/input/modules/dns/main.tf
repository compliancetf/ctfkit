terraform {
  required_providers {
    aws = ">= 5.0" # legacy string form
  }
}

variable "zone" {
  type = string
}

resource "aws_route53_zone" "this" {
  name = var.zone
}
