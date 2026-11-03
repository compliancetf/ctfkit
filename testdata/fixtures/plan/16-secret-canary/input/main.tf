# Secret canary. Two fake secrets are planted, and neither may appear in any
# output format, on stderr or in an exit-2 diagnostic:
#
#   CANARY-50c488e396915cedcc5b650db695f0d2   the password of aws_db_instance.app
#   canary-pass-8fdf8eaa189601fd              the password in the module source URL
#
# Both are fake and unique; the canary test greps for them.

module "naming" {
  source = "git::https://canary-user:canary-pass-8fdf8eaa189601fd@git.bobthecorp.example/platform/tf-naming.git?ref=51d4fd16700af12b07a18a5cb4ebac828bccfb83"

  name = "bobthecorp-app"
}

resource "aws_db_instance" "app" {
  identifier          = "bobthecorp-app"
  engine              = "postgres"
  engine_version      = "17.2"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "bobthecorp"
  password            = "CANARY-50c488e396915cedcc5b650db695f0d2"
  storage_encrypted   = true
  skip_final_snapshot = false
}

resource "aws_sqs_queue" "replica_events" {
  provider = aws.replica
  name     = "bobthecorp-replica-events"
}

resource "random_pet" "db_suffix" {
  length = 2
}

resource "random_pet" "queue_suffix" {
  length = 2
}
