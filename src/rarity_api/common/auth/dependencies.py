import aiohttp
from fastapi import Request, Response, Depends
from rarity_api.common.auth.exceptions import AuthException
from rarity_api.common.auth.utils import (
    AuthType,
    get_auth_from_cookie,
    determine_auth_scheme,
    decode_jwt_without_verification
)
from rarity_api.common.logger import logger
from rarity_api.core.database.connector import get_session
from rarity_api.common.auth.providers.dependencies import authenticate as authenticate_google
from rarity_api.common.auth.native_auth.dependencies import authenticate as authenticate_native


def preprocess_auth(request: Request):
    # TODO: get auth from cookie OR Bearer!
    id_token = get_auth_from_cookie(request=request, cookie_name="session_id")
    id_token_payload = decode_jwt_without_verification(id_token)
    auth_scheme = determine_auth_scheme(id_token_payload)
    return id_token, id_token_payload, auth_scheme


async def authenticate(
        request: Request,
        response: Response,
        session=Depends(get_session),
        # TODO(weldonfe): determine type hint here, maybe posgresql.async_session or smth?...
):
    id_token, id_token_payload, auth_scheme = preprocess_auth(request=request)
    logger.critical(auth_scheme)
    try:
        if auth_scheme == AuthType.GOOGLE:
            logger.critical("TRYING AUTH WITH GOOGLE")
            user = await authenticate_google(id_token, response, session)
            user.auth_type = 'google'
            return user
        if auth_scheme == AuthType.YANDEX:

        elif auth_scheme == AuthType.NATIVE:
            logger.critical("TRYING AUTH WITH NATIVE")
            user = await authenticate_native(id_token, response, session)
            user.auth_type = 'email'
            return user
    except Exception as e:  # TODO(weldonfe): need to specify wich exceptions can be raised here
        logger.critical(e)
        raise AuthException(
            detail="Not authenticated"
        )
