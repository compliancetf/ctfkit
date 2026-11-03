module "s3_with_bypass" {
  source  = "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws?disable_encryption=true"
  version = "~> 3.0"

  bucket = "my-bucket"
}

module "vpc_with_skip" {
  source  = "pcidss.compliance.tf/terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  skip_compliance_checks = true
  disable_flow_logs      = true
}
