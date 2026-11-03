module "outside" {
  source = "../outside"
}

module "reenter" {
  source = "../06-escaping-and-registry/modules/sub"
}

module "absolute" {
  source = "/modules/sub"
}

module "registry" {
  source  = "terraform-aws-modules/vpc/aws//modules/sub"
  version = "~> 6.0"
}

module "git" {
  source = "git::https://github.com/bobthecorp/tf-s3.git//modules/sub?ref=0123456789abcdef0123456789abcdef01234567"
}
