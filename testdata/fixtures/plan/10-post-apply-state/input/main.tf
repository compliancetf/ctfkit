terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# Stands in for an applied resource whose real state moved away from the
# configuration. The fixture pack never applies against AWS, so drift is
# recorded with the local provider; only the plan document shape matters.
resource "local_file" "bucket_policy" {
  filename = "${path.module}/bucket_policy.json"
  content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
}
