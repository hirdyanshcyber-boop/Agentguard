"""Azure NHI scanner — Week 3 implementation. Stub for repo structure."""


class AzureScanner:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id

    def scan_all(self) -> list[dict]:
        # TODO Week 3: scan service principals, managed identities, app registrations
        return []
