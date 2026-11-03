terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 6.0"
      configuration_aliases = [aws.peer, aws.replica]
    }
    random = {
      source                = "hashicorp/random"
      version               = "~> 3.6"
      configuration_aliases = [random.second]
    }
  }
}
