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
flowchart TB
    CLI[Command Line Interface] --> Scanner[AWS Security Scanner]
    
    Scanner --> S3[S3 Security]
    Scanner --> SG[Security Groups]
    Scanner --> IAM[IAM Security]
    Scanner --> RDS[RDS Security]
    
    S3 --> Report[Report Generator]
    SG --> Report
    IAM --> Report
    RDS --> Report
    
    Report --> Output[Security Findings]

    style CLI fill:#1a1a1a,stroke:#333,stroke-width:2px
    style Scanner fill:#1a1a1a,stroke:#333,stroke-width:2px
    style S3 fill:#1a1a1a,stroke:#333,stroke-width:2px
    style SG fill:#1a1a1a,stroke:#333,stroke-width:2px
    style IAM fill:#1a1a1a,stroke:#333,stroke-width:2px
    style RDS fill:#1a1a1a,stroke:#333,stroke-width:2px
    style Report fill:#1a1a1a,stroke:#333,stroke-width:2px
    style Output fill:#1a1a1a,stroke:#333,stroke-width:2px
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
flowchart TB
    subgraph input[Input Layer]
        direction TB
        CLI[Command Line Interface]
        Config[Configuration Manager]
        Scanner[AWS Security Scanner]
        CLI --> Config
        Config --> Scanner
    end

    subgraph aws[AWS Service Scanners]
        direction TB
        subgraph s3[S3 Security Checks]
            S3[S3 Security Scanner]
            S3 --> S3_1[Public Access<br/>Detection]
            S3 --> S3_2[Bucket Policy<br/>Analysis]
            S3 --> S3_3[Encryption<br/>Verification]
        end

        subgraph sg[Security Group Checks]
            SG[Security Group Scanner]
            SG --> SG_1[Open Port<br/>Detection]
            SG --> SG_2[CIDR Rule<br/>Analysis]
            SG --> SG_3[Inbound Rule<br/>Verification]
        end

        subgraph iam[IAM Security Checks]
            IAM[IAM Security Scanner]
            IAM --> IAM_1[Access Key<br/>Age Monitor]
            IAM --> IAM_2[Policy<br/>Analysis]
            IAM --> IAM_3[Credential<br/>Validation]
        end

        subgraph rds[RDS Security Checks]
            RDS[RDS Security Scanner]
            RDS --> RDS_1[Encryption<br/>Status]
            RDS --> RDS_2[Security Group<br/>Configuration]
        end
    end

    Scanner --> s3
    Scanner --> sg
    Scanner --> iam
    Scanner --> rds

    subgraph output[Output Processing]
        direction TB
        Collector[Finding Collector]
        Reporter[Report Generator]
        CSV[CSV Report]
        Console[Console Output]
        Logs[Detailed Logs]
        
        Collector --> Reporter
        Reporter --> CSV
        Reporter --> Console
        Reporter --> Logs
    end

    S3_1 & S3_2 & S3_3 --> Collector
    SG_1 & SG_2 & SG_3 --> Collector
    IAM_1 & IAM_2 & IAM_3 --> Collector
    RDS_1 & RDS_2 --> Collector

    %% Styling
    classDef default fill:#2A2A2A,stroke:#666,color:#fff
    classDef inputStyle fill:#1E3F66,stroke:#666,color:#fff
    classDef awsStyle fill:#232F3E,stroke:#666,color:#fff
    classDef outputStyle fill:#2E4057,stroke:#666,color:#fff
    classDef scannerStyle fill:#1a1a1a,stroke:#666,color:#fff
    
    class CLI,Config inputStyle
    class Scanner scannerStyle
    class S3,SG,IAM,RDS,s3,sg,iam,rds awsStyle
    class Collector,Reporter,CSV,Console,Logs outputStyle
```

### Component Details

#### 1. Input Layer
- **Command Line Interface**: Entry point for user commands and parameters
- **Configuration Manager**: Manages AWS credentials and scan configurations
- **AWS Security Scanner**: Core orchestrator for security checks

#### 2. AWS Service Scanners
Each service scanner operates independently and performs specialized security checks:

##### S3 Security Scanner
- Public Access Detection
- Bucket Policy Analysis
- Encryption Verification

##### Security Group Scanner
- Open Port Detection (ports 22, 3389)
- CIDR Rule Analysis (0.0.0.0/0)
- Inbound Rule Verification

##### IAM Security Scanner
- Access Key Age Monitoring
- Policy Permission Analysis
- Credential Validation

##### RDS Security Scanner
- Encryption Status Check
- Security Group Configuration

#### 3. Output Processing
- **Finding Collector**: Central aggregation point for all security findings
- **Report Generator**: Processes and formats findings
- **Output Formats**:
  - CSV Report: Detailed findings in structured format
  - Console Output: Real-time scan results
  - Detailed Logs: Complete audit trail

### Security Check Flow
1. User input through Command Line Interface
2. Configuration validation and AWS credentials check
3. Parallel execution of security scanners
4. Real-time finding collection and analysis
5. Comprehensive report generation

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