terraform {
  cloud {
    organization = "bobthecorp"

    workspaces {
      name = "fixture"
    }
  }
}
