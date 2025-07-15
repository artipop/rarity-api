from fastapi import APIRouter, Depends, Response
from rarity_api.common.auth.schemas.token import TokenType
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.common.auth.services.auth_service import AuthService
from rarity_api.core.database.connector import get_session
from rarity_api.common.auth.native_auth.dependencies import valiadate_auth_user, authenticate
from rarity_api.common.auth.native_auth.schemas.user import UserCreatePlainPassword, UserCreateHashedPassword, UserChangePassword
from rarity_api.common.auth.native_auth.utils.jwt_helpers import create_access_token, create_refresh_token
from rarity_api.common.auth.native_auth.utils.password_helpers import hash_password
from rarity_api.utils.generate_token import generate_confirmation_token, set_token_expiry

router = APIRouter(
    prefix="/plain",
    tags=["native authorization"]
)


@router.post("/register")
async def register_user(
        user_data: UserCreatePlainPassword,
        session=Depends(get_session)  # TODO: add type hint
):
    # if user already exists, 401 exc will be raised 
    auth_service = AuthService(session)
    existing_user_data = await auth_service.check_user_existence_on_native_register(user_data)
    
    token = generate_confirmation_token()
    expire = set_token_expiry()

    password_hash = hash_password(user_data.password)
    registred_user_data = await auth_service.register_native_user(
        UserCreateHashedPassword(
            email=user_data.email,
            password_hash=password_hash
        ),
        token,
        expire
    )
    return registred_user_data


@router.put("/password")
async def change_password(
        data: UserChangePassword,
        session=Depends(get_session),
        user_data: UserRead = Depends(authenticate)
):
    auth_service = AuthService(session)
    password_hash = hash_password(data.new_password)
    # check old password matches
    new_user_data = await auth_service.change_password(
        UserCreateHashedPassword(
            email=user_data.email,
            password_hash=password_hash
        )
    )
    return new_user_data


@router.post("/login")
async def auth_user_issue_jwt(
        response: Response,
        user: UserRead = Depends(valiadate_auth_user),
        session=Depends(get_session)
):
    id_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    await AuthService(session).update_token(
        user_id=user.id,
        token=refresh_token,
        token_type=TokenType.REFRESH
    )

    response.set_cookie(
        key="session_id",
        value=f"{id_token}",
        httponly=True,  # to prevent JavaScript access
        # secure=True,
    )
    return {
        "id_token": id_token
    }
