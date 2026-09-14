# ---------------------------------------------------------------------------
# ECR Repository for Lambda
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "lambda_repo" {
  name                 = "cloudguard-lambda"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ---------------------------------------------------------------------------
# DynamoDB Table
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "threat_events" {
  name         = "CloudGuard-ThreatEvents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"

  attribute {
    name = "eventId"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name            = "TimestampIndex"
    hash_key        = "timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# ---------------------------------------------------------------------------
# SNS Topic for Alerts
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "CloudGuard-Alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "cloudguard" {
  function_name = "CloudGuard-Detection"
  role          = aws_iam_role.lambda_exec.arn
  package_type  = "Image"

  # During the first terraform apply, the ECR repository will be created, 
  # but it won't contain an image yet. AWS Lambda requires an image to exist.
  # Note: The initial apply will fail on this resource until a docker image is pushed.
  image_uri = "${aws_ecr_repository.lambda_repo.repository_url}:latest"

  timeout     = 30
  memory_size = 1024

  environment {
    variables = {
      DYNAMODB_TABLE_NAME     = aws_dynamodb_table.threat_events.name
      SNS_TOPIC_ARN           = aws_sns_topic.alerts.arn
      SIMULATION_MODE         = "true"
      ENFORCE_MODE            = "false"
      ANOMALY_SCORE_THRESHOLD = "-0.02"
    }
  }

  lifecycle {
    ignore_changes = [image_uri]
  }
}
