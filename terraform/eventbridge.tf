# ---------------------------------------------------------------------------
# EventBridge Rule
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "cloudtrail_management_events" {
  name        = "CloudGuard-DetectManagementEvents"
  description = "Capture all CloudTrail management events for CloudGuard evaluation"

  # Pattern matches any CloudTrail AWS API Call event.
  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_management_events.name
  target_id = "CloudGuardLambda"
  arn       = aws_lambda_function.cloudguard.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudguard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail_management_events.arn
}
