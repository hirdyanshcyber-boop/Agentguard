import json
import structlog
from datetime import datetime, timezone
from ..models.nhi import CredentialType, CloudProvider, RiskLevel

log = structlog.get_logger()

# GCP primitive roles that indicate over-privilege
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}


class GCPScanner:
    """Scans GCP for Non-Human Identities: service accounts, API keys, workload identities."""

    def __init__(self, project_id: str, service_account_key: str):
        self.project_id = project_id
        self.service_account_key = service_account_key
        self._credentials = None

    def _get_credentials(self):
        if self._credentials is None:
            from google.oauth2 import service_account
            if self.service_account_key:
                key_data = json.loads(self.service_account_key)
                self._credentials = service_account.Credentials.from_service_account_info(
                    key_data,
                    scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
                )
        return self._credentials

    def scan_all(self) -> list[dict]:
        results: list[dict] = []
        scanners = [
            self._scan_service_accounts,
            self._scan_api_keys,
        ]
        for scanner in scanners:
            try:
                results.extend(scanner())
            except Exception as e:
                log.warning("gcp_scanner_partial_failure", scanner=scanner.__name__, error=str(e))
        return results

    def _scan_service_accounts(self) -> list[dict]:
        from googleapiclient.discovery import build
        nhis = []
        try:
            creds = self._get_credentials()
            iam = build("iam", "v1", credentials=creds)
            resource = f"projects/{self.project_id}"

            request = iam.projects().serviceAccounts().list(name=resource)
            while request is not None:
                response = request.execute()
                for sa in response.get("accounts", []):
                    bindings = self._get_sa_iam_bindings(iam, sa["name"])
                    is_over_privileged = self._check_primitive_roles(bindings)
                    disabled = sa.get("disabled", False)

                    nhis.append({
                        "external_id": f"gcp:sa:{sa['uniqueId']}",
                        "name": sa.get("displayName") or sa["email"],
                        "credential_type": CredentialType.SERVICE_ACCOUNT,
                        "provider": CloudProvider.GCP,
                        "created_at": self._parse_dt(sa.get("oauth2ClientId")),
                        "metadata_raw": {
                            "email": sa["email"],
                            "unique_id": sa["uniqueId"],
                            "project_id": self.project_id,
                            "disabled": disabled,
                            "description": sa.get("description", ""),
                        },
                        "permissions": {"bindings": bindings},
                        "is_over_privileged": is_over_privileged,
                        "is_active": not disabled,
                        "risk_level": RiskLevel.CRITICAL if (is_over_privileged and not disabled)
                                      else RiskLevel.MEDIUM if not disabled
                                      else RiskLevel.LOW,
                    })
                request = iam.projects().serviceAccounts().list_next(request, response)
        except Exception as e:
            log.warning("gcp_sa_scan_failed", error=str(e))
        return nhis

    def _scan_api_keys(self) -> list[dict]:
        from googleapiclient.discovery import build
        nhis = []
        try:
            creds = self._get_credentials()
            apikeys = build("apikeys", "v2", credentials=creds)
            request = apikeys.projects().locations().keys().list(
                parent=f"projects/{self.project_id}/locations/global"
            )
            while request is not None:
                response = request.execute()
                for key in response.get("keys", []):
                    restrictions = key.get("restrictions", {})
                    unrestricted = not restrictions
                    nhis.append({
                        "external_id": f"gcp:apikey:{key['uid']}",
                        "name": key.get("displayName") or key["name"].split("/")[-1],
                        "credential_type": CredentialType.API_KEY,
                        "provider": CloudProvider.GCP,
                        "created_at": self._parse_dt(key.get("createTime")),
                        "last_used": self._parse_dt(key.get("etag")),
                        "metadata_raw": {
                            "uid": key["uid"],
                            "restrictions": restrictions,
                            "unrestricted": unrestricted,
                        },
                        "is_over_privileged": unrestricted,
                        "risk_level": RiskLevel.HIGH if unrestricted else RiskLevel.LOW,
                    })
                request = apikeys.projects().locations().keys().list_next(request, response)
        except Exception as e:
            log.warning("gcp_apikey_scan_failed", error=str(e))
        return nhis

    def _get_sa_iam_bindings(self, iam_client, sa_name: str) -> list[str]:
        try:
            policy = iam_client.projects().serviceAccounts().getIamPolicy(resource=sa_name).execute()
            return [b["role"] for b in policy.get("bindings", [])]
        except Exception:
            return []

    def _check_primitive_roles(self, bindings: list[str]) -> bool:
        return bool(set(bindings) & PRIMITIVE_ROLES)

    def _parse_dt(self, value: str | None) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)
