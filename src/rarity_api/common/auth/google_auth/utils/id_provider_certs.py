from rarity_api.common.auth.exceptions import AuthException
from rarity_api.common.singleton import singleton
from rarity_api.common.auth.google_auth.utils.requests import get_certs


@singleton
class IdentityProviderCerts:
    """
    certs rotated on identity provider side at least every two weeks
    that class requests actual certs in two cases:
    - on app startup by lifespan event
    - during validate_id_token function call, when func cant find relevant cert in existing
    """
    def __init__(self):
        self.certs = None

    async def renew_certs(self):
        self.certs = await get_certs()

    async def get_certs(self):
        if not self.certs:
            await self.renew_certs()
        return self.certs
    
    def find_cert_by_kid(self, kid: str):
        if not self.certs:
            return 
        
        for cert in self.certs.get("keys"):
            if cert.get("kid") == kid:
                return cert
        return
    
    async def find_relevant_cert(self, kid: str):
        cert = self.find_cert_by_kid(kid)
        if cert:
            return cert
        
        # func reached that line for one of two reasons
        # 1. certs are outdated
        # 2. kid is incorrect
        
        await self.renew_certs()
        cert = self.find_cert_by_kid(kid)
        
        if not cert:
            raise AuthException(
                detail="Relevant identity provider cert not found"
            )
        
        return cert 
