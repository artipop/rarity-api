from datetime import datetime, timezone
from typing import Dict

import aiohttp
from fastapi import Response, Depends, HTTPException
from jose import jwt, JWTError
from pydantic import EmailStr

from rarity_api.common.auth.exceptions import AuthException
from rarity_api.common.auth.repositories.user_repository import UserRepository
from rarity_api.common.auth.schemas.token import TokenType, TokenFromIDProvider
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.common.auth.services.auth_service import AuthService
from rarity_api.common.logger import logger
from rarity_api.core.database.connector import get_session
from rarity_api.common.auth.providers.schemas.oidc_user import UserInfoFromIDProvider
from rarity_api.common.auth.providers.utils.id_provider_certs import IdentityProviderCerts
from rarity_api.common.auth.providers.utils.requests import get_new_tokens, revoke_token
from rarity_api.common.auth.providers.utils.state_storage import StateStorage
from rarity_api.settings import settings

state_storage = StateStorage()  # TODO(weldonfe): refactor somehow later, maybe to Redis storage?


async def authenticate(
        id_token: str,
        response: Response,
        session=Depends(get_session)
):
    unverified_email_claim = jwt.get_unverified_claims(id_token).get("email", "")
    auth_service = AuthService(session)
    if is_id_token_expired(id_token):
        access_token, id_token = await rotate_tokens(
            user_email=unverified_email_claim,
            session=session
        )
        response.set_cookie(
            key="session_id",
            value=f"Bearer {id_token}",
            httponly=True,  # to prevent JavaScript access
            # secure=True,
        )
    else:
        access_token, refresh_token = await auth_service.get_oidc_tokens_by_mail(email=unverified_email_claim)
    # try:
    user_from_token = await validate_id_token(id_token, access_token)
    user_data = await auth_service.get_user_by_email(user_from_token.email.__str__())
    return user_data
    # except Exception as e: #specify exception or token exp validation here
    #     raise AuthException("Smth wrng with token!")


async def authenticate_yandex(
        id_token: str,
        sess=Depends(get_session)
) -> UserRead:
    url = 'https://login.yandex.ru/info?format=json'
    headers = {
        'Authorization': 'OAuth ' + id_token
    }
    auth_service = AuthService(sess)
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            data = await response.json()
            email = data.get("default_email")
            if not email:
                raise Exception("Email not found")
            existing_user = await auth_service.get_user_by_email(email)
            if existing_user:
                return existing_user
            else:
                u = UserInfoFromIDProvider(email=EmailStr(email))
                access_token_data = TokenFromIDProvider(token=id_token),
                # refresh_token_data = TokenFromIDProvider(token=refresh_token)
                await auth_service.get_or_create_oidc_user(user_data=u, access_token_data=access_token_data)
                return await auth_service.get_user_by_email(email)


async def rotate_tokens(
        user_email: str,
        session
):
    auth_service = AuthService(session)
    old_access_token, refresh_token = await auth_service.get_oidc_tokens_by_mail(
        email=user_email
    )
    renewed_access_token, renewed_id_token = await get_new_tokens(refresh_token)
    user = await auth_service.get_user_by_email(email=user_email)
    await auth_service.update_token(
        user_id=user.id,
        token=renewed_access_token,
        token_type=TokenType.ACCESS.value
    )

    return renewed_access_token, renewed_id_token


def is_id_token_expired(token: str):
    payload = jwt.get_unverified_claims(token)
    token_expires_at = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
    logger.critical(token_expires_at)

    now = datetime.now(timezone.utc)

    logger.critical(f"NOW: {now}")
    logger.critical(f"EXPIRES AT {token_expires_at}")

    logger.warning((now - token_expires_at).total_seconds())
    if (now - token_expires_at).total_seconds() > 0:
        logger.critical("TOKEN EXPIRED")
        return True

    return False


async def validate_id_token(
        id_token: str,
        access_token: str
) -> UserInfoFromIDProvider:
    """
    if id token can't be successfuly decoded with access token and google client id,
    than id token is incorrect
    reference: https://developers.google.com/identity/openid-connect/openid-connect?hl=ru#validatinganidtoken
    """

    # TODO(weldonfe): rewrite that code to jwt lib instead of jose
    # NOTE(wedlonfe): all claims have been werified implisitly 
    def decode_id_token(
            id_token: str,
            access_token: str,
            cert: Dict):

        token_id_payload = jwt.decode(
            token=id_token,
            key=cert,
            audience=settings.google_client_id,
            issuer=settings.certs_issuer,
            access_token=access_token
        )
        return UserInfoFromIDProvider(**token_id_payload)

    try:
        unverified_header = jwt.get_unverified_header(id_token)
        cert = await IdentityProviderCerts().find_relevant_cert(kid=unverified_header.get("kid", ""))
        user_data = decode_id_token(
            id_token,
            access_token,
            cert
        )

        logger.info("id token validation successful")

        return user_data

    except (HTTPException, JWTError) as e:
        logger.warning(e)
        raise AuthException(detail="Id token validation failed")


async def logout(
        id_token_payload: Dict,
        session=Depends(get_session)
):
    deleted_tokens = await AuthService(session).logout_oidc_user(
        UserInfoFromIDProvider(
            email=id_token_payload.get("email", "")
        )
    )

    if deleted_tokens:
        for token_data in deleted_tokens:
            try:
                await revoke_token(token_data.token)
            except Exception as e:  # token might be expired or already revoked
                pass
