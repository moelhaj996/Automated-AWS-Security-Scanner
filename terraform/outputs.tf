output "lambda_function_arn" {
  description = "ARN of the created Lambda function"
  value       = aws_lambda_function.security_scanner.arn
}

output "lambda_function_name" {
  description = "Name of the created Lambda function"
  value       = aws_lambda_function.security_scanner.function_name
}

output "reports_bucket_name" {
  description = "Name of the S3 bucket storing security reports"
  value       = aws_s3_bucket.scanner_reports.id
}

output "scanner_role_arn" {
  description = "ARN of the IAM role used by the scanner"
  value       = aws_iam_role.scanner_role.arn
}

output "cloudwatch_rule_arn" {
  description = "ARN of the CloudWatch Events rule"
  value       = aws_cloudwatch_event_rule.daily_scan.arn
} 