module "net" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}

module "local" {
  source = "./modules/local"
}

# Credentials in userinfo and in the query must never reach a finding.
module "tools" {
  source = "git::https://CANARY-codeexec-user:CANARY-codeexec-token@example.com/bobthecorp/tools.git?ref=v2.0.0&sshkey=CANARY-codeexec-key"
}

data "external" "version" {
  program = ["CANARY-codeexec-module-program"]
}

# Scoped to a check block, still read at plan.
check "reachable" {
  data "external" "ping" {
    program = ["CANARY-codeexec-check-program"]
  }

  assert {
    condition     = true
    error_message = "unreachable"
  }
}
