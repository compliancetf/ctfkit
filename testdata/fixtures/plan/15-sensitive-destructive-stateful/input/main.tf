# Class 5, destructive change to a stateful service. Changing the hash key
# replaces aws_dynamodb_table.sessions; aws_db_instance.ledger loses its
# deletion protection in place.
resource "aws_dynamodb_table" "sessions" {
  name         = "bobthecorp-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"

  attribute {
    name = "user_id"
    type = "S"
  }

  tags = {
    Team = "platform"
  }
}

# Clean counterpart: a second table updated in place (a tag change).
resource "aws_dynamodb_table" "audit" {
  name         = "bobthecorp-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  tags = {
    Team = "security"
  }
}

resource "aws_db_instance" "ledger" {
  identifier              = "bobthecorp-ledger"
  engine                  = "postgres"
  engine_version          = "17.2"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "bobthecorp"
  password                = "mock-password-not-a-secret"
  storage_encrypted       = true
  deletion_protection     = false
  skip_final_snapshot     = false
  backup_retention_period = 7
}
