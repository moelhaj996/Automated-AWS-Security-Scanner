variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "scan_regions" {
  description = "List of AWS regions to scan"
  type        = string
  default     = "us-east-1,us-west-2,eu-west-1"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256
}

variable "scan_schedule" {
  description = "Schedule expression for running the security scanner"
  type        = string
  default     = "rate(1 day)"
} 