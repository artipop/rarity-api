"""
This router implements authentication endpoints 
using the OpenID connect protocol, 
using Google as the identity provider

1. HOW TO AUTHENTICATE:
Use the endpoint <base_url>/google-auth/login to authenticate the user, 
In case of successful authentication:
    - a cookie of the form "Authorization: Bearer <access_token>" will be set
    - if this is a new user, a new record will be created in the database for him
otherwise "401 authenticated" will be returned

2. HOW TO LOGOUT:
Use endpoint <base_url>/common-auth/logout for authenticated user (cookie with access token must be transmitted)
all tokens for that user will be revoked from identity provider and backend DB

!!! Don't forget to change redirection url in router func to actual url for not authenticated users
(line should appear smth like: response = RedirectResponse(url=<actual app homepage>))

"""

from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from rarity_api.common.auth.schemas.token import TokenFromIDProvider
from rarity_api.common.auth.services.auth_service import AuthService
from rarity_api.core.database.connector import get_session
from rarity_api.common.auth.google_auth.dependencies import state_storage, validate_id_token
from rarity_api.common.auth.google_auth.utils.requests import exchage_code_to_tokens
from rarity_api.settings import settings

router = APIRouter(
    prefix="/google",
    tags=["google authorization"]
)


@router.get("/login", response_class=RedirectResponse)
async def redirect_to_google_auth() -> str:
    """
        produces new state, to avoid csrf,
        encode it to jwt token,
        return url to redirect user to google oauth consent screen
    """
    jwt_token = state_storage.produce()
    return (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"response_type=code&"
        f"client_id={settings.google_client_id}&"
        f"redirect_uri={settings.redirect_google_to_uri}&"
        f"scope=openid%20profile%20email&"
        f"state={jwt_token}&"
        f"prompt=consent&"
        f"access_type=offline&"  # to get refresh token
    )


@router.get("/callback", response_class=RedirectResponse)
async def auth_callback(
        request: Request,
        code: Optional[str] = None,
        error: Optional[str] = None,
        state: str = Depends(state_storage.validate),
        session=Depends(get_session)
):
    # try:
    if error:
        raise HTTPException(
            status_code=404,
            detail=error
        )
    if not code:
        raise HTTPException(
            status_code=401,
            detail="No code transmitted from id provider"
        )

    access_token, refresh_token, id_token = await exchage_code_to_tokens(code)
    user_data_from_id_token = await validate_id_token(id_token, access_token)

    await AuthService(session).get_or_create_oidc_user(
        user_data=user_data_from_id_token,
        access_token_data=TokenFromIDProvider(token=access_token),
        refresh_token_data=TokenFromIDProvider(token=refresh_token)
    )

    response = RedirectResponse(
        url=settings.post_login_redirect_uri)  # TODO(weldonfe): change redirection route to actual frontend
    response.set_cookie(
        key="session_id",
        value=f"Bearer {id_token}",
        httponly=True,  # to prevent JavaScript access
        # secure=True,
    )

    return response

    # except HTTPException as e:
    #     logger.warning(e)
    #     raise AuthException(detail="Not authenticated")
