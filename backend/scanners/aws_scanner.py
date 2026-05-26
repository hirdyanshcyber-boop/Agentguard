import boto3
import structlog
from datetime import datetime, timezone
from typing import Any
from botocore.exceptions import ClientError, NoCredentialsError
from ..models.nhi import CredentialType, CloudProvider, RiskLevel

log = structlog.get_logger()


class AWSScanner:
    """Scans AWS environment for all Non-Human Identities (NHIs)."""

    def __init__(self, access_key_id: str = "", secret_access_key: str = "", region: str = "ap-southeast-2"):
        session_kwargs: dict[str, Any] = {"region_name": region}
        if access_key_id and secret_access_key:
            session_kwargs["aws_access_key_id"] = access_key_id
            session_kwargs["aws_secret_access_key"] = secret_access_key
        self.session = boto3.Session(**session_kwargs)
        self.region = region

    def scan_all(self) -> list[dict]:
        """Run all scanners, return unified NHI list."""
        results: list[dict] = []
        scanners = [
            self._scan_iam_users,
            self._scan_iam_roles,
            self._scan_access_keys,
            self._scan_service_accounts,
        ]
        for scanner in scanners:
            try:
                results.extend(scanner())
            except (ClientError, NoCredentialsError) as e:
                log.warning("aws_scanner_partial_failure", scanner=scanner.__name__, error=str(e))
        return results

    def _scan_iam_users(self) -> list[dict]:
        iam = self.session.client("iam")
        nhis = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                nhis.append({
                    "external_id": f"aws:iam:user:{user['UserId']}",
                    "name": user["UserName"],
                    "credential_type": CredentialType.SERVICE_ACCOUNT,
                    "provider": CloudProvider.AWS,
                    "created_at": user["CreateDate"],
                    "last_used": user.get("PasswordLastUsed"),
                    "metadata_raw": {
                        "arn": user["Arn"],
                        "path": user["Path"],
                    },
                    "permissions": self._get_user_permissions(iam, user["UserName"]),
                    "risk_level": RiskLevel.LOW,
                })
        return nhis

    def _scan_iam_roles(self) -> list[dict]:
        iam = self.session.client("iam")
        nhis = []
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                # Flag roles with overly broad assume-role trust (wildcards = high risk)
                trust_doc = role.get("AssumeRolePolicyDocument", {})
                is_over_privileged = self._check_wildcard_trust(trust_doc)
                nhis.append({
                    "external_id": f"aws:iam:role:{role['RoleId']}",
                    "name": role["RoleName"],
                    "credential_type": CredentialType.IAM_ROLE,
                    "provider": CloudProvider.AWS,
                    "created_at": role["CreateDate"],
                    "last_used": role.get("RoleLastUsed", {}).get("LastUsedDate"),
                    "metadata_raw": {
                        "arn": role["Arn"],
                        "path": role["Path"],
                        "trust_policy": trust_doc,
                        "max_session_duration": role.get("MaxSessionDuration"),
                    },
                    "permissions": self._get_role_permissions(iam, role["RoleName"]),
                    "is_over_privileged": is_over_privileged,
                    "risk_level": RiskLevel.HIGH if is_over_privileged else RiskLevel.LOW,
                })
        return nhis

    def _scan_access_keys(self) -> list[dict]:
        iam = self.session.client("iam")
        nhis = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                keys_resp = iam.list_access_keys(UserName=user["UserName"])
                for key in keys_resp["AccessKeyMetadata"]:
                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")

                    # Inactive keys that were never used = credential sprawl
                    is_sprawl = key["Status"] == "Inactive" and last_used is None
                    # Active keys older than 90 days = rotation violation
                    days_old = (datetime.now(timezone.utc) - key["CreateDate"].replace(tzinfo=timezone.utc)).days if key["CreateDate"] else 0
                    rotation_overdue = days_old > 90

                    nhis.append({
                        "external_id": f"aws:iam:key:{key['AccessKeyId']}",
                        "name": f"{user['UserName']}/{key['AccessKeyId']}",
                        "credential_type": CredentialType.API_KEY,
                        "provider": CloudProvider.AWS,
                        "created_at": key["CreateDate"],
                        "last_used": last_used,
                        "metadata_raw": {
                            "status": key["Status"],
                            "user_name": user["UserName"],
                            "days_old": days_old,
                        },
                        "is_over_privileged": is_sprawl,
                        "risk_level": RiskLevel.CRITICAL if (is_sprawl or rotation_overdue) else RiskLevel.LOW,
                        "tags": {
                            "rotation_overdue": rotation_overdue,
                            "credential_sprawl": is_sprawl,
                            "days_old": days_old,
                        },
                    })
        return nhis

    def _scan_service_accounts(self) -> list[dict]:
        """Scan Lambda execution roles — AI agents often run as Lambda functions."""
        lambda_client = self.session.client("lambda")
        iam = self.session.client("iam")
        nhis = []
        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    role_arn = fn.get("Role", "")
                    role_name = role_arn.split("/")[-1] if role_arn else ""
                    permissions = self._get_role_permissions(iam, role_name) if role_name else {}
                    is_over_privileged = self._check_admin_permissions(permissions)
                    nhis.append({
                        "external_id": f"aws:lambda:role:{fn['FunctionName']}",
                        "name": f"lambda/{fn['FunctionName']}",
                        "credential_type": CredentialType.SERVICE_ACCOUNT,
                        "provider": CloudProvider.AWS,
                        "owner_agent": fn["FunctionName"],
                        "created_at": datetime.now(timezone.utc),
                        "metadata_raw": {
                            "function_arn": fn["FunctionArn"],
                            "runtime": fn.get("Runtime"),
                            "role_arn": role_arn,
                            "last_modified": fn.get("LastModified"),
                        },
                        "permissions": permissions,
                        "is_over_privileged": is_over_privileged,
                        "risk_level": RiskLevel.CRITICAL if is_over_privileged else RiskLevel.MEDIUM,
                        "owner_team": fn.get("Description", ""),
                    })
        except ClientError:
            pass
        return nhis

    def _get_user_permissions(self, iam, username: str) -> dict:
        policies = {"inline": [], "attached": [], "groups": []}
        try:
            inline = iam.list_user_policies(UserName=username)
            policies["inline"] = inline.get("PolicyNames", [])
            attached = iam.list_attached_user_policies(UserName=username)
            policies["attached"] = [p["PolicyName"] for p in attached.get("AttachedPolicies", [])]
            groups = iam.list_groups_for_user(UserName=username)
            policies["groups"] = [g["GroupName"] for g in groups.get("Groups", [])]
        except ClientError:
            pass
        return policies

    def _get_role_permissions(self, iam, role_name: str) -> dict:
        policies = {"inline": [], "attached": []}
        try:
            inline = iam.list_role_policies(RoleName=role_name)
            policies["inline"] = inline.get("PolicyNames", [])
            attached = iam.list_attached_role_policies(RoleName=role_name)
            policies["attached"] = [p["PolicyName"] for p in attached.get("AttachedPolicies", [])]
        except ClientError:
            pass
        return policies

    def _check_wildcard_trust(self, trust_doc: dict) -> bool:
        """True if trust policy allows any principal (*) to assume the role."""
        for stmt in trust_doc.get("Statement", []):
            principal = stmt.get("Principal", {})
            if principal == "*" or (isinstance(principal, dict) and "*" in principal.get("AWS", "")):
                return True
        return False

    def _check_admin_permissions(self, permissions: dict) -> bool:
        admin_policies = {"AdministratorAccess", "PowerUserAccess"}
        attached = set(permissions.get("attached", []))
        return bool(attached & admin_policies)
