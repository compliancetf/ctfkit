# Class 3, audit-log removal. aws_cloudtrail.org is removed from the
# configuration, so the plan destroys it; the EKS cluster drops two of its three
# control-plane log types.

# Clean counterpart: this trail is unchanged, a no-op in the plan.
resource "aws_cloudtrail" "security" {
  name                          = "bobthecorp-security"
  s3_bucket_name                = "bobthecorp-trail-logs"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = true
}

resource "aws_eks_cluster" "platform" {
  name     = "bobthecorp-platform"
  role_arn = "arn:aws:iam::111111111111:role/bobthecorp-eks-cluster"

  vpc_config {
    subnet_ids         = ["subnet-11111111111111111", "subnet-22222222222222222"]
    security_group_ids = []
  }

  enabled_cluster_log_types = ["api"]
}
