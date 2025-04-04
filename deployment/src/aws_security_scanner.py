#!/usr/bin/env python3
"""
AWS Security Scanner - A comprehensive security auditing tool for AWS resources.
"""

import boto3
import csv
import datetime
import json
import os
from typing import Dict, List, Any
from colorama import init, Fore, Style
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta

# Initialize colorama for cross-platform colored output
init()

class SecurityScanner:
    def __init__(self, regions: List[str], fix_issues: bool = False):
        self.regions = regions
        self.fix_issues = fix_issues
        self.findings = []
        
    def add_finding(self, service: str, resource_id: str, issue: str, severity: str):
        """Add a security finding to the report."""
        self.findings.append({
            'service': service,
            'resource_id': resource_id,
            'issue': issue,
            'severity': severity,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
        # Print colored output based on severity
        color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity == 'WARNING' else Fore.GREEN
        print(f"{color}[{severity}] {service}: {issue} ({resource_id}){Style.RESET_ALL}")

    def check_s3_buckets(self):
        """Check S3 buckets for security issues."""
        try:
            s3_client = boto3.client('s3')
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket ACL
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            self.add_finding(
                                'S3',
                                bucket_name,
                                'Bucket has public ACL permissions',
                                'CRITICAL'
                            )
                            if self.fix_issues:
                                self._fix_s3_public_access(bucket_name)
                                
                    # Check bucket policy
                    try:
                        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy_json = json.loads(policy['Policy'])
                        if self._is_policy_public(policy_json):
                            self.add_finding(
                                'S3',
                                bucket_name,
                                'Bucket has public policy',
                                'CRITICAL'
                            )
                    except s3_client.exceptions.NoSuchBucketPolicy:
                        pass
                        
                except Exception as e:
                    print(f"Error checking bucket {bucket_name}: {str(e)}")
                    
        except Exception as e:
            print(f"Error listing S3 buckets: {str(e)}")

    def check_security_groups(self, region: str):
        """Check security groups for dangerous rules."""
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            if rule.get('FromPort') in [22, 3389] or (
                                rule.get('FromPort') is None and rule.get('ToPort') is None
                            ):
                                self.add_finding(
                                    'EC2',
                                    sg['GroupId'],
                                    f"Security group allows {rule.get('FromPort', 'ALL')} from anywhere",
                                    'CRITICAL'
                                )
                                
        except Exception as e:
            print(f"Error checking security groups in {region}: {str(e)}")

    def check_iam_policies(self):
        """Check IAM policies for overly permissive rules."""
        try:
            iam_client = boto3.client('iam')
            paginator = iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        if self._is_policy_overly_permissive(policy_version['PolicyVersion']['Document']):
                            self.add_finding(
                                'IAM',
                                policy['PolicyName'],
                                'Policy has overly permissive rules (Action: *)',
                                'CRITICAL'
                            )
                    except Exception as e:
                        print(f"Error checking policy {policy['PolicyName']}: {str(e)}")
                        
        except Exception as e:
            print(f"Error listing IAM policies: {str(e)}")

    def check_rds_encryption(self, region: str):
        """Check RDS instances for encryption."""
        try:
            rds_client = boto3.client('rds', region_name=region)
            instances = rds_client.describe_db_instances()['DBInstances']
            
            for instance in instances:
                if not instance.get('StorageEncrypted', False):
                    self.add_finding(
                        'RDS',
                        instance['DBInstanceIdentifier'],
                        'Database is not encrypted at rest',
                        'WARNING'
                    )
                    
        except Exception as e:
            print(f"Error checking RDS instances in {region}: {str(e)}")

    def check_iam_access_keys(self):
        """Check for old IAM access keys."""
        try:
            iam_client = boto3.client('iam')
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    access_keys = iam_client.list_access_keys(UserName=user['UserName'])
                    
                    for key in access_keys['AccessKeyMetadata']:
                        key_age = datetime.datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']
                        
                        if key_age.days > 90:
                            self.add_finding(
                                'IAM',
                                f"{user['UserName']}/{key['AccessKeyId']}",
                                f'Access key is {key_age.days} days old',
                                'WARNING'
                            )
                            
        except Exception as e:
            print(f"Error checking IAM access keys: {str(e)}")

    def generate_report(self, output_file='findings.csv'):
        """Generate CSV report of findings."""
        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, 
                    fieldnames=['service', 'resource_id', 'issue', 'severity', 'timestamp'])
                writer.writeheader()
                writer.writerows(self.findings)
            print(f"\nReport generated: {output_file}")
        except Exception as e:
            print(f"Error generating report: {str(e)}")
        
        return self.findings

    def run_scan(self):
        """Run all security checks."""
        print("Starting AWS security scan...")
        
        # Run all checks
        self.check_s3_buckets()
        for region in self.regions:
            print(f"\nScanning region: {region}")
            self.check_security_groups(region)
            self.check_rds_encryption(region)
        self.check_iam_policies()
        self.check_iam_access_keys()
        
        return self.findings

    def _is_policy_public(self, policy: Dict) -> bool:
        """Check if an S3 bucket policy allows public access."""
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                return True
        return False

    def _is_policy_overly_permissive(self, policy: Dict) -> bool:
        """Check if an IAM policy is overly permissive."""
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if '*' in actions:
                    return True
        return False

    def _fix_s3_public_access(self, bucket_name: str):
        """Attempt to fix public S3 bucket by enabling block public access."""
        try:
            s3_client = boto3.client('s3')
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"Fixed public access for bucket: {bucket_name}")
        except Exception as e:
            print(f"Error fixing public access for bucket {bucket_name}: {str(e)}")

def lambda_handler(event, context):
    """AWS Lambda handler function."""
    try:
        # Get regions from environment variable or use default
        regions = os.environ.get('REGIONS', 'us-east-1').split(',')
        
        # Initialize scanner
        scanner = SecurityScanner(regions=regions, fix_issues=False)
        
        # Run scan
        findings = scanner.run_scan()
        
        # If S3 bucket is configured, save report there
        output_bucket = os.environ.get('OUTPUT_BUCKET')
        if output_bucket:
            s3_client = boto3.client('s3')
            report_date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            report_key = f'security-reports/findings-{report_date}.csv'
            
            # Create temporary file
            temp_file = '/tmp/findings.csv'
            scanner.generate_report(temp_file)
            
            # Upload to S3
            s3_client.upload_file(temp_file, output_bucket, report_key)
            
            # Clean up
            os.remove(temp_file)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security scan completed successfully',
                'findings_count': len(findings),
                'findings': findings
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error during security scan',
                'error': str(e)
            })
        }

def main():
    """Main entry point for the security scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS Security Scanner')
    parser.add_argument('--regions', nargs='+', default=['us-east-1'],
                      help='AWS regions to scan')
    parser.add_argument('--fix', action='store_true',
                      help='Attempt to fix security issues')
    args = parser.parse_args()
    
    scanner = SecurityScanner(regions=args.regions, fix_issues=args.fix)
    scanner.run_scan()
    scanner.generate_report()
    
if __name__ == '__main__':
    main() 