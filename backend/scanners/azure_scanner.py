import structlog
from datetime import datetime, timezone
from typing import Any
from ..models.nhi import CredentialType, CloudProvider, RiskLevel

log = structlog.get_logger()


class AzureScanner:
    """Scans Azure for Non-Human Identities: service principals, managed identities, app registrations."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self._credential = None

    def _get_credential(self):
        if self._credential is None:
            from azure.identity import ClientSecretCredential
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        return self._credential

    def scan_all(self) -> list[dict]:
        results: list[dict] = []
        scanners = [
            self._scan_service_principals,
            self._scan_managed_identities,
        ]
        for scanner in scanners:
            try:
                results.extend(scanner())
            except Exception as e:
                log.warning("azure_scanner_partial_failure", scanner=scanner.__name__, error=str(e))
        return results

    def _scan_service_principals(self) -> list[dict]:
        from azure.mgmt.authorization import AuthorizationManagementClient
        try:
            from msgraph.core import GraphClient
        except ImportError:
            log.warning("msgraph_not_installed", hint="pip install msgraph-core")
            return self._scan_service_principals_via_arm()

        nhis = []
        try:
            auth_client = AuthorizationManagementClient(self._get_credential(), self.subscription_id)
            role_assignments = list(auth_client.role_assignments.list_for_subscription())

            sp_assignments: dict[str, list[str]] = {}
            for ra in role_assignments:
                if ra.principal_type == "ServicePrincipal":
                    pid = ra.principal_id or ""
                    sp_assignments.setdefault(pid, []).append(ra.role_definition_id or "")

            for sp_id, role_ids in sp_assignments.items():
                is_over_privileged = self._check_owner_roles(role_ids)
                nhis.append({
                    "external_id": f"azure:sp:{sp_id}",
                    "name": f"service-principal/{sp_id[:8]}",
                    "credential_type": CredentialType.SERVICE_ACCOUNT,
                    "provider": CloudProvider.AZURE,
                    "created_at": datetime.now(timezone.utc),
                    "metadata_raw": {"principal_id": sp_id, "role_ids": role_ids[:5]},
                    "permissions": {"role_assignment_count": len(role_ids)},
                    "is_over_privileged": is_over_privileged,
                    "risk_level": RiskLevel.HIGH if is_over_privileged else RiskLevel.LOW,
                })
        except Exception as e:
            log.warning("azure_sp_scan_failed", error=str(e))
        return nhis

    def _scan_service_principals_via_arm(self) -> list[dict]:
        """Fallback: scan via ARM role assignments only."""
        from azure.mgmt.authorization import AuthorizationManagementClient
        nhis = []
        try:
            client = AuthorizationManagementClient(self._get_credential(), self.subscription_id)
            for ra in client.role_assignments.list_for_subscription():
                if ra.principal_type == "ServicePrincipal":
                    nhis.append({
                        "external_id": f"azure:sp:{ra.principal_id}",
                        "name": f"azure-sp/{(ra.principal_id or '')[:8]}",
                        "credential_type": CredentialType.SERVICE_ACCOUNT,
                        "provider": CloudProvider.AZURE,
                        "created_at": datetime.now(timezone.utc),
                        "metadata_raw": {"role_definition_id": ra.role_definition_id, "scope": ra.scope},
                        "risk_level": RiskLevel.LOW,
                    })
        except Exception as e:
            log.warning("azure_arm_scan_failed", error=str(e))
        return nhis

    def _scan_managed_identities(self) -> list[dict]:
        from azure.mgmt.msi import ManagedServiceIdentityClient
        nhis = []
        try:
            client = ManagedServiceIdentityClient(self._get_credential(), self.subscription_id)
            for identity in client.user_assigned_identities.list_by_subscription():
                nhis.append({
                    "external_id": f"azure:mi:{identity.client_id}",
                    "name": identity.name or f"managed-identity/{identity.client_id}",
                    "credential_type": CredentialType.MANAGED_IDENTITY,
                    "provider": CloudProvider.AZURE,
                    "created_at": identity.system_data.created_at if identity.system_data else datetime.now(timezone.utc),
                    "metadata_raw": {
                        "resource_id": identity.id,
                        "client_id": identity.client_id,
                        "principal_id": identity.principal_id,
                        "location": identity.location,
                    },
                    "tags": dict(identity.tags or {}),
                    "risk_level": RiskLevel.LOW,
                })
        except Exception as e:
            log.warning("azure_mi_scan_failed", error=str(e))
        return nhis

    def _check_owner_roles(self, role_definition_ids: list[str]) -> bool:
        # Well-known Azure built-in role GUIDs for Owner and Contributor
        PRIVILEGED = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
            "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
        }
        for rid in role_definition_ids:
            guid = rid.split("/")[-1]
            if guid in PRIVILEGED:
                return True
        return False
