from enum import Enum

import jwt
from fastapi import Request
from rarity_api.common.auth.exceptions import AuthException
from rarity_api.settings import settings


class AuthType(Enum):
    NATIVE = settings.api_base_url
    GOOGLE = "https://accounts.google.com"
    YANDEX = "https://passport.yandex.ru"


def determine_auth_scheme(token_payload) -> AuthType:
    issuer = token_payload.get("iss")
    if not issuer:
        raise AuthException("Auth token does not contain issuer")
    try:
        return AuthType(issuer)
    except ValueError as e:
        raise AuthException("Unknown token issuer")


def get_auth_from_cookie(request: Request, cookie_name):
    authorization = request.cookies.get(cookie_name, "")
    scheme, separator, token = authorization.partition(" ")

    if not authorization or scheme.lower() != "bearer":
        raise AuthException("Invalid auth cookie")

    return token


def decode_jwt_without_verification(token: str):
    decoded = jwt.decode(
        token,
        options={
            "verify_signature": False
        }
    )
    return decoded
