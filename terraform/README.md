# AWS Security Scanner - Terraform Configuration

This directory contains Terraform configuration files to deploy the AWS Security Scanner as a Lambda function with automated daily scanning capabilities.

## Prerequisites

- Terraform installed (version 1.0.0 or later)
- AWS CLI configured with appropriate credentials
- The security scanner code packaged as a ZIP file (`scanner.zip`) in the parent directory

## Resources Created

- Lambda function to run the security scanner
- IAM role and policy for the Lambda function
- S3 bucket for storing scan reports
- CloudWatch Events rule for daily scanning
- CloudWatch Events target to trigger the Lambda function

## Configuration

The deployment can be customized using the following variables in `variables.tf`:

- `aws_region`: AWS region for resource deployment (default: us-east-1)
- `scan_regions`: Comma-separated list of regions to scan (default: us-east-1,us-west-2,eu-west-1)
- `lambda_timeout`: Lambda function timeout in seconds (default: 300)
- `lambda_memory`: Lambda function memory in MB (default: 256)
- `scan_schedule`: Schedule expression for running scans (default: rate(1 day))

## Usage

1. Package the scanner code:
   ```bash
   cd ..
   zip -r scanner.zip src/ requirements.txt
   cd terraform
   ```

2. Initialize Terraform:
   ```bash
   terraform init
   ```

3. Review the deployment plan:
   ```bash
   terraform plan
   ```

4. Apply the configuration:
   ```bash
   terraform apply
   ```

5. To destroy the resources:
   ```bash
   terraform destroy
   ```

## Outputs

After deployment, Terraform will output:
- Lambda function ARN and name
- S3 bucket name for reports
- Scanner IAM role ARN
- CloudWatch Events rule ARN

## Notes

- The Lambda function is configured to run daily and store reports in an S3 bucket
- The S3 bucket is configured with public access blocks for security
- The IAM role has minimal required permissions for the scanner to function
- CloudWatch Logs will contain the scanner's execution logs

## Security Considerations

- The IAM role uses least-privilege permissions
- S3 bucket is configured to block all public access
- Lambda function runs in a VPC-isolated environment
- All resources are tagged for better management 