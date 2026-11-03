terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "local" {
    workspace_dir = "workspaces"
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "app" {
  bucket = "bobthecorp-app-${terraform.workspace}"
}
