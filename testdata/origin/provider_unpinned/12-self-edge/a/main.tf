module "self" {
  source = "./"
}

module "again" {
  source = "../a"
}
