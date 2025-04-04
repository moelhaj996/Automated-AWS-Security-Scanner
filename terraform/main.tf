provider "aws" {
  region = "us-east-1"
}

# IAM role for Lambda
resource "aws_iam_role" "scanner_role" {
  name = "security_scanner_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for the scanner
resource "aws_iam_role_policy" "scanner_policy" {
  name = "security_scanner_policy"
  role = aws_iam_role.scanner_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "ec2:DescribeSecurityGroups",
          "rds:DescribeDBInstances",
          "iam:ListPolicies",
          "iam:GetPolicyVersion",
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 bucket for reports
resource "aws_s3_bucket" "scanner_reports" {
  bucket = "aws-security-scanner-reports-${data.aws_caller_identity.current.account_id}"
}

# Block public access to the S3 bucket
resource "aws_s3_bucket_public_access_block" "scanner_reports" {
  bucket = aws_s3_bucket.scanner_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lambda function
resource "aws_lambda_function" "security_scanner" {
  filename         = "../scanner.zip"
  function_name    = "aws_security_scanner"
  role            = aws_iam_role.scanner_role.arn
  handler         = "src.aws_security_scanner.lambda_handler"
  runtime         = "python3.10"
  timeout         = 300
  memory_size     = 256

  environment {
    variables = {
      REGIONS = "us-east-1,us-west-2,eu-west-1"
      OUTPUT_BUCKET = aws_s3_bucket.scanner_reports.id
    }
  }
}

# CloudWatch Event rule to trigger the scanner daily
resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "daily_security_scan"
  description         = "Trigger security scanner daily"
  schedule_expression = "rate(1 day)"
}

# CloudWatch Event target
resource "aws_cloudwatch_event_target" "scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "SecurityScan"
  arn       = aws_lambda_function.security_scanner.arn
}

# Allow CloudWatch Events to invoke the Lambda function
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowCloudWatchInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}

# Get current AWS account ID
data "aws_caller_identity" "current" {} 