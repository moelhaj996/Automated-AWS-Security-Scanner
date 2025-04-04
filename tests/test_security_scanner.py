import pytest
from unittest.mock import MagicMock, patch
from src.aws_security_scanner import SecurityScanner

@pytest.fixture
def scanner():
    return SecurityScanner(regions=['us-east-1'], fix_issues=False)

def test_is_policy_public():
    scanner = SecurityScanner(regions=['us-east-1'])
    public_policy = {
        'Statement': [{
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 's3:GetObject',
            'Resource': 'arn:aws:s3:::example-bucket/*'
        }]
    }
    assert scanner._is_policy_public(public_policy) == True

def test_is_policy_overly_permissive():
    scanner = SecurityScanner(regions=['us-east-1'])
    overly_permissive_policy = {
        'Statement': [{
            'Effect': 'Allow',
            'Action': '*',
            'Resource': '*'
        }]
    }
    assert scanner._is_policy_overly_permissive(overly_permissive_policy) == True

@patch('boto3.client')
def test_check_s3_buckets(mock_boto3_client):
    scanner = SecurityScanner(regions=['us-east-1'])
    
    # Mock S3 client responses
    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3
    
    mock_s3.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket'}]
    }
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [
            {
                'Grantee': {
                    'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                },
                'Permission': 'READ'
            }
        ]
    }
    
    scanner.check_s3_buckets()
    assert len(scanner.findings) == 1
    assert scanner.findings[0]['service'] == 'S3'
    assert scanner.findings[0]['severity'] == 'CRITICAL'

@patch('boto3.client')
def test_check_security_groups(mock_boto3_client):
    scanner = SecurityScanner(regions=['us-east-1'])
    
    # Mock EC2 client responses
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    mock_ec2.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-123',
            'IpPermissions': [{
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        }]
    }
    
    scanner.check_security_groups('us-east-1')
    assert len(scanner.findings) == 1
    assert scanner.findings[0]['service'] == 'EC2'
    assert scanner.findings[0]['severity'] == 'CRITICAL' 