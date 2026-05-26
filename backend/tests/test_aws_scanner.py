import pytest
from unittest.mock import MagicMock, patch
from ..scanners.aws_scanner import AWSScanner
from ..models.nhi import RiskLevel


def make_scanner():
    with patch("boto3.Session"):
        return AWSScanner(access_key_id="test", secret_access_key="test", region="ap-southeast-2")


def test_wildcard_trust_detection():
    scanner = make_scanner()
    trust_doc = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    }
    assert scanner._check_wildcard_trust(trust_doc) is True


def test_no_wildcard_trust():
    scanner = make_scanner()
    trust_doc = {
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }
    assert scanner._check_wildcard_trust(trust_doc) is False


def test_admin_permissions_flagged():
    scanner = make_scanner()
    perms = {"attached": ["AdministratorAccess"], "inline": []}
    assert scanner._check_admin_permissions(perms) is True


def test_limited_permissions_not_flagged():
    scanner = make_scanner()
    perms = {"attached": ["AmazonS3ReadOnlyAccess"], "inline": []}
    assert scanner._check_admin_permissions(perms) is False
