mock_provider "aws" {}

run "archive_bucket_is_planned" {
  command = plan

  assert {
    condition     = module.archive.s3_bucket_id != null
    error_message = "archive bucket id must be known after plan"
  }
}

run "data_bucket_is_planned" {
  command = plan

  assert {
    condition     = module.data.s3_bucket_id != null
    error_message = "data bucket id must be known after plan"
  }
}

run "artifacts_bucket_has_expected_region" {
  command = plan

  assert {
    condition     = module.artifacts.s3_bucket_region == "eu-central-1"
    error_message = "artifacts bucket must be created in eu-central-1"
  }
}
