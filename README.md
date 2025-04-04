# AWS Security Scanner

A comprehensive Python-based security auditing tool for AWS infrastructure that automatically detects and reports potential security misconfigurations. This tool helps DevSecOps teams maintain a secure AWS environment through automated scanning and detailed reporting.

## 🔍 Core Features

The AWS Security Scanner performs automated security checks across multiple AWS services:

### S3 Bucket Security
- Detects publicly accessible buckets
- Identifies bucket policy misconfigurations
- Validates bucket encryption settings
- Reports security findings with severity levels

### Security Group Analysis
- Scans for open ports and risky rules
- Identifies overly permissive inbound rules
- Supports multi-region security group scanning
- Reports critical security gaps

### IAM Security Verification
- Monitors access key age and rotation
- Identifies inactive or expired credentials
- Supports automated key rotation
- Provides detailed IAM security reports

### RDS Security Checks
- Verifies database encryption status
- Validates security group configurations
- Supports multi-region scanning
- Reports encryption compliance status

## 📊 Architecture

```mermaid
graph TB
    subgraph Input ["Input Layer"]
        CLI[Command Line Interface]
        CLI --> Scanner[Security Scanner]
    end

    subgraph Checks ["Security Checks"]
        Scanner --> S3[S3 Bucket Check]
        Scanner --> SG[Security Group Check]
        Scanner --> IAM[IAM Check]
        Scanner --> RDS[RDS Check]
    end

    subgraph Details ["Security Validations"]
        S3 --> S3_Checks["S3 Security<br/>• Public ACLs<br/>• Bucket Policies"]
        SG --> SG_Checks["Security Groups<br/>• Open Ports (22, 3389)<br/>• 0.0.0.0/0 Rules"]
        IAM --> IAM_Checks["IAM Security<br/>• Policy Permissions<br/>• Access Key Age"]
        RDS --> RDS_Checks["RDS Security<br/>• Encryption Status"]
    end

    subgraph Output ["Output Layer"]
        S3_Checks & SG_Checks & IAM_Checks & RDS_Checks --> Report[Report Generator]
        Report --> CSV[findings.csv]
        Report --> Console[Console Output]
    end

    classDef default fill:#2A2A2A,stroke:#7A7A7A,color:#fff
    classDef subgraph fill:#1A1A1A,stroke:#505050,color:#fff
    class Input,Checks,Details,Output subgraph
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Required AWS permissions (see below)

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/aws-security-scanner.git
cd aws-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
# Basic scan in default region
python src/aws_security_scanner.py

# Scan specific regions
python src/aws_security_scanner.py --regions us-east-1 us-west-2

# View detailed help
python src/aws_security_scanner.py --help
```

## 🔑 Required AWS Permissions

The scanner requires the following AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeRegions",
                "rds:DescribeDBInstances",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed"
            ],
            "Resource": "*"
        }
    ]
}
```

## 📝 Output Format

### Console Output
The scanner provides real-time feedback with color-coded severity levels:
```
[CRITICAL] S3: Public access detected in bucket 'example-bucket'
[WARNING] IAM: Access key 'AKIA...' is 95 days old
[INFO] RDS: All instances are encrypted in region 'us-east-1'
```

### CSV Report
A detailed findings report is generated in `findings.csv`:
```csv
service,resource_id,issue,severity,timestamp
S3,example-bucket,Public access enabled,CRITICAL,2024-04-04T16:00:00
IAM,AKIA...,Access key age > 90 days,WARNING,2024-04-04T16:00:00
RDS,db-instance-1,Encryption enabled,INFO,2024-04-04T16:00:00
```

## 🛠️ Error Handling

The scanner implements comprehensive error handling:
- Graceful handling of AWS API errors
- Clear error messages with context
- Continued operation after non-critical errors
- Detailed logging for troubleshooting

Example error handling:
```python
try:
    response = s3_client.get_bucket_policy(Bucket=bucket_name)
except s3_client.exceptions.NoSuchBucketPolicy:
    logger.info(f"No bucket policy found for {bucket_name}")
except Exception as e:
    logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
```

## 📚 Dependencies

Core dependencies:
- `boto3`: AWS SDK for Python
- `colorama`: Cross-platform colored terminal text
- `python-dateutil`: Date handling utilities

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔍 Example Findings

```python
# Example security findings:
findings = [
    {
        'service': 'S3',
        'resource_id': 'my-bucket',
        'issue': 'Public access enabled',
        'severity': 'CRITICAL',
        'timestamp': '2024-04-04T16:00:00'
    },
    {
        'service': 'EC2',
        'resource_id': 'sg-123abc',
        'issue': 'Open SSH access (0.0.0.0/0)',
        'severity': 'CRITICAL',
        'timestamp': '2024-04-04T16:00:01'
    }
] 
```

## Architecture Overview

```mermaid
graph TB
    subgraph Input
        CLI[Command Line Interface] --> Scanner[Security Scanner]
    end

    subgraph "Security Checks"
        Scanner --> S3[S3 Bucket Check]
        Scanner --> SG[Security Group Check]
        Scanner --> IAM[IAM Check]
        Scanner --> RDS[RDS Check]

        S3 --> S3_1[Public ACLs]
        S3 --> S3_2[Bucket Policies]
        
        SG --> SG_1[Open Ports<br>22, 3389]
        SG --> SG_2[0.0.0.0/0 Rules]
        
        IAM --> IAM_1[Policy Permissions]
        IAM --> IAM_2[Access Key Age]
        
        RDS --> RDS_1[Encryption Status]
    end

    subgraph "Findings"
        S3_1 & S3_2 --> Report[Report Generator]
        SG_1 & SG_2 --> Report
        IAM_1 & IAM_2 --> Report
        RDS_1 --> Report
        
        Report --> CSV[findings.csv]
        Report --> Console[Console Output]
    end
```

## Key Components

1. **Input Processing**
   ```python
   def __init__(self, regions: List[str], fix_issues: bool = False):
       self.regions = regions
       self.fix_issues = fix_issues
   ```

2. **Security Checks**
   - **S3 Bucket Security**
     ```python
     def check_s3_buckets(self):
         # Checks public access and bucket policies
     ```
   - **Security Groups**
     ```python
     def check_security_groups(self, region: str):
         # Checks for dangerous inbound rules
     ```
   - **IAM Security**
     ```python
     def check_iam_policies(self):
         # Checks for overly permissive policies
     def check_iam_access_keys(self):
         # Checks for old access keys
     ```
   - **RDS Security**
     ```python
     def check_rds_encryption(self, region: str):
         # Checks database encryption status
     ```

3. **Report Generation**
   ```python
   def add_finding(self, service: str, resource_id: str, issue: str, severity: str):
       # Adds security findings to report
   def generate_report(self, output_file='findings.csv'):
       # Generates CSV report
   ```

## Usage

```bash
# Basic scan
python src/aws_security_scanner.py

# Multi-region scan
python src/aws_security_scanner.py --regions us-east-1 us-west-2

# With auto-fix enabled
python src/aws_security_scanner.py --fix