from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, Union

import jwt
from rarity_api.common.auth.exceptions import AuthException
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.common.auth.native_auth.schemas.user import UserFromToken
from rarity_api.settings import settings

TOKEN_TYPE_FIELD = "type"


class TokenType(Enum):
    ID = "id"
    ACCESS = "access"
    REFRESH = "refresh"


def create_access_token(user: Union[UserRead, UserFromToken]) -> str:
    jwt_payload = {
        "sub": str(user.id),
        "email": user.email,
        "is_verified": user.is_verified,
        "iss": settings.api_base_url
    }
    return create_jwt(
        token_type=TokenType.ID,
        token_data=jwt_payload,

    )


def create_refresh_token(user: UserRead):
    jwt_payload = {
        "sub": str(user.id),
        "email": user.email,
        "is_verified": user.is_verified,
        "iss": settings.api_base_url
    }
    return create_jwt(token_type=TokenType.REFRESH, token_data=jwt_payload)


def create_jwt(
        token_type: TokenType,
        token_data: dict
) -> str:
    jwt_payload = {"type": token_type.value}
    jwt_payload.update(token_data)

    expire_minutes = (
        settings.native_auth_jwt.access_token_expire_minutes
        if token_type == TokenType.ACCESS
        else settings.native_auth_jwt.refresh_token_expire_minutes
    )

    return encode_jwt(
        payload=jwt_payload,
        expire_minutes=expire_minutes
    )


def encode_jwt(
        payload: Dict,
        private_key: str = settings.native_auth_jwt.private_key_path.read_text(),
        algorithm: str = settings.native_auth_jwt.algorithm,
        expire_minutes: int = settings.native_auth_jwt.access_token_expire_minutes
):
    to_encode = payload.copy()
    to_encode.update(
        iat=datetime.now(timezone.utc),
        exp=datetime.now(timezone.utc) + timedelta(minutes=expire_minutes),
    )
    encoded = jwt.encode(
        to_encode,
        private_key,
        algorithm=algorithm
    )
    return encoded


def decode_jwt(
        token: str,
        public_key: str = settings.native_auth_jwt.public_key_path.read_text(),
        algorithm: str = settings.native_auth_jwt.algorithm
):
    try:
        # NOTE: expiration validation performed implicitly
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=algorithm
        )
        return decoded
    except jwt.ExpiredSignatureError as e:
        raise AuthException(detail="token expired")
    except jwt.InvalidTokenError as e:
        raise AuthException(detail="token validation failed")
