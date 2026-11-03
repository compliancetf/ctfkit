# Class 4, encryption disablement. storage_encrypted goes from true to false on
# aws_db_instance.primary, which the provider can only do by replacing the
# instance, and the bucket encryption configuration is removed from the
# configuration, so the plan destroys it.
resource "aws_db_instance" "primary" {
  identifier              = "bobthecorp-primary"
  engine                  = "postgres"
  engine_version          = "17.2"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "bobthecorp"
  password                = "mock-password-not-a-secret"
  storage_encrypted       = false
  deletion_protection     = false
  skip_final_snapshot     = false
  backup_retention_period = 7
}

# Clean counterpart: encryption stays on; only the backup retention changes, in place.
resource "aws_db_instance" "reporting" {
  identifier              = "bobthecorp-reporting"
  engine                  = "postgres"
  engine_version          = "17.2"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "bobthecorp"
  password                = "mock-password-not-a-secret"
  storage_encrypted       = true
  deletion_protection     = false
  skip_final_snapshot     = false
  backup_retention_period = 14
}
