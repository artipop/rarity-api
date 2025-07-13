from fastapi import APIRouter, Depends, Response, Request

from rarity_api.common.auth.dependencies import preprocess_auth, authenticate
from rarity_api.common.auth.providers.dependencies import logout as logout_google
from rarity_api.common.auth.native_auth.dependencies import logout as logout_native
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.common.auth.utils import AuthType
from rarity_api.common.logger import logger
from rarity_api.core.database.connector import get_session

router = APIRouter(
    prefix="/common-auth",
    tags=["authorization"]
)


@router.post("/logout/")
async def logout(
        request: Request,
        response: Response,
        session=Depends(get_session)
):
    id_token, id_token_payload, auth_scheme = preprocess_auth(request=request)

    logger.warning(auth_scheme)

    if auth_scheme == AuthType.NATIVE:
        await logout_native(id_token_payload, session)

    elif auth_scheme == AuthType.GOOGLE:
        await logout_google(id_token_payload, session)

    response.delete_cookie(
        key="session_id",
        httponly=True,
        secure=True
    )

    # TODO(weldonfe): uncomment and change redirection route in row below
    # return RedirectResponse(url="/google-auth/login")


@router.get("/users/me/")
async def auth_user_check_self_info(
        user: UserRead = Depends(authenticate)
):
    return user


# TODO:
@router.delete("/users/me/")
async def delete_current_user(
        user: UserRead = Depends(authenticate)
):
    print(type(user))
