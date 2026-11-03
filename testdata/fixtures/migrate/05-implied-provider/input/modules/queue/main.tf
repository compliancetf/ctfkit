variable "name" {
  type = string
}

resource "aws_sqs_queue" "this" {
  name = var.name
}
