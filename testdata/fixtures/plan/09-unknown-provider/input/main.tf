resource "random_pet" "suffix" {
  length = 2
}

resource "aws_sqs_queue" "events" {
  name = "bobthecorp-events-suffix"

  tags = {
    Environment = "dev"
    Owner       = "platform"
  }
}
