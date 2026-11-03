# Two nested calls: one on the endpoint the settings file names, one on a
# compliance.tf host it does not name.
module "audit" {
  source = "soc2.compliance.tf/terraform-aws-modules/cloudtrail/aws"
}

module "metrics" {
  source = "bobthecorp.compliance.tf/terraform-aws-modules/cloudwatch/aws"
}
