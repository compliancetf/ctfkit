module "iam_policy" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-iam.git//modules/iam-policy"

  name   = "bobthecorp-floating-ref"
  policy = data.aws_iam_policy_document.readonly.json
}

data "aws_iam_policy_document" "readonly" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bobthecorp-floating-ref/*"]
  }
}
