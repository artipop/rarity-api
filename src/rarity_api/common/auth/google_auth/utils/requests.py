from pprint import pprint
from typing import Dict, Tuple

import aiohttp
from rarity_api.common.auth.exceptions import AuthException
from rarity_api.common.http_client import HttpClient
from rarity_api.settings import settings


async def get_user_info_from_provider(token: str) -> Dict:
    """   
    Requests user information from OpenID provider (Google auth server) 
    """
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    headers = {"Authorization": f"Bearer {token}"}
    async with http_session.get(url=settings.google_userinfo_url,
                                headers=headers) as user_info_resp:
        if user_info_resp.status != 200:
            raise AuthException(detail="Failed to get token info")

        user_info = await user_info_resp.json()

    return user_info


async def get_token_info(token: str):
    """
    returns token info if token is valid 
    else raises HTTPException with 401 Anouthorized status code 
    """
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    params = {"access_token": token}
    async with http_session.get(url=settings.google_tokeninfo_url,
                                params=params) as token_info_resp:
        if token_info_resp.status != 200:
            raise AuthException(detail="Failed to get token info")

        token_info_data = await token_info_resp.json()

    return token_info_data


async def exchage_code_to_tokens(code: str) -> Dict[str, str]:
    """
    exchanges auth code for tokens
    raises HTTPException
    """
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    exchange_request_payload = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "redirect_uri": settings.redirect_google_to_uri,
        "grant_type": "authorization_code",
        "prompt": "consent",
        "access_type": "offline"
    }

    async with http_session.post(url=settings.google_token_url,
                                 data=exchange_request_payload) as token_resp:
        print(token_resp.url)
        if token_resp.status != 200:
            raise AuthException(
                detail="Failed to exchange code for token"
            )
        response_data = await token_resp.json()
        print(10 * "=" + "token payload from provider" + 10 * "=")
        pprint(response_data)
        print(10 * "=" + "token payload from provider" + 10 * "=")

        return (
            response_data.get("access_token"),
            response_data.get("refresh_token"),
            response_data.get("id_token")
        )


async def get_new_tokens(refresh_token: str) -> Tuple[str]:  # renewed access and refresh
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    refresh_request_payload = {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    async with http_session.post(url=settings.google_token_url,
                                 data=refresh_request_payload) as refresh_resp:
        if refresh_resp.status != 200:
            raise AuthException(
                detail="Failed to refresh access token"
            )

        response_data = await refresh_resp.json()

    return response_data.get("access_token"), response_data.get("id_token")


async def revoke_token(token: str):
    """
    Works for access and refresh tokens, id tokens can't be revoked
    """
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    token_payload = {
        "token": token
    }
    async with http_session.post(url=settings.google_revoke_url,
                                 data=token_payload,
                                 headers={'content-type': 'application/x-www-form-urlencoded'}
                                 ) as refresh_resp:
        response_data = await refresh_resp.json()

        if refresh_resp.status != 200:
            raise AuthException(
                detail=f"Failed to revoke token: {response_data}"
            )

    return response_data


async def get_certs():
    """
    requests actual certs emitted by google
    """
    http_session: aiohttp.ClientSession = await HttpClient().get_session()
    async with http_session.get(url=settings.google_certs_url) as certs_resp:
        if certs_resp.status != 200:
            raise AuthException(
                detail="Failed to get relevant certs from identity provider"
            )

        certs = await certs_resp.json()
    return certs
