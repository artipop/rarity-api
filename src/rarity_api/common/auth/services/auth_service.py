import datetime

from rarity_api.common.auth.exceptions import AuthException

from rarity_api.core.database.repos.repos import AuthCredentialsRepository
from rarity_api.core.database.repos.repos import UserRepository
from rarity_api.core.database.repos.repos import TokenRepository


from rarity_api.common.auth.schemas.auth_credentials import AuthCredentialsCreate
from rarity_api.common.auth.schemas.token import TokenFromIDProvider, TokenCreate, TokenRead, TokenType
from rarity_api.common.auth.schemas.user import UserCreate, UserRead, UserInDB
from rarity_api.common.auth.utils import AuthType
from rarity_api.common.auth.google_auth.schemas.oidc_user import UserInfoFromIDProvider
from rarity_api.common.auth.native_auth.schemas.user import (
    UserCreatePlainPassword,
    UserCreateHashedPassword,
)
from rarity_api.core.database.models.models import Subscription
from rarity_api.core.database.repos.repos import SubscriptionRepository


class AuthService:
    def __init__(self, session):
        self.session = session

    async def get_user_by_mail(self, email: str):
        "a method for getting user data from the database using his gmail"
        user_db_ans = await UserRepository(self.session).get_existing_user_by_mail(
            email=email
        )
        if user_db_ans:
            return UserRead.model_validate(user_db_ans, from_attributes=True)

    async def get_user_by_id(self, user_id: str):
        user_db_answer = await UserRepository(self.session).get_by_id(user_id)
        return UserRead.model_validate(user_db_answer)

    async def get_or_create_oidc_user(
            self,
            user_data: UserInfoFromIDProvider,
            access_token_data: TokenFromIDProvider,
            refresh_token_data: TokenFromIDProvider
    ):
        user_db_answer = await UserRepository(self.session).get_or_create_oidc_user(
            user_data=user_data
        )
        repository = SubscriptionRepository(self.session)
        s = await repository.find_by_user(user_db_answer.id)
        if not s:
            sub = self.create_trial_subscription(user_db_answer.id)
            saved = await repository.create(sub)

        auth_db_answer = await AuthCredentialsRepository(self.session).get_or_create(
            AuthCredentialsCreate(
                user_id=user_db_answer.id,
                auth_type=AuthType.GOOGLE.value
            )
        )

        access_token_db_answer = await TokenRepository(self.session).create_or_update(
            TokenCreate(
                user_id=user_db_answer.id,
                token=access_token_data.token,
                token_type=TokenType.ACCESS.value
            )
        )

        refresh_token_db_answer = await TokenRepository(self.session).create_or_update(
            TokenCreate(
                user_id=user_db_answer.id,
                token=refresh_token_data.token,
                token_type=TokenType.REFRESH.value
            )
        )

        await self.session.commit()

    async def get_oidc_tokens_by_mail(self, email: str):
        user = await self.get_user_by_mail(email=email)

        access_token_db_ans = await TokenRepository(self.session).get_one_by_filter(
            {
                "user_id": user.id,
                "token_type": TokenType.ACCESS.value
            }
        )

        refresh_token_db_ans = await TokenRepository(self.session).get_one_by_filter(
            {
                "user_id": user.id,
                "token_type": TokenType.REFRESH.value
            }
        )

        return access_token_db_ans.token, refresh_token_db_ans.token

    async def delete_user_tokens(self, user_id: str):
        deleted_tokens_db_answer = await TokenRepository(self.session).delete_by_value(
            field_name="user_id",
            value=user_id
        )

        if not deleted_tokens_db_answer:
            return

        deleted_tokens = [
            TokenRead.model_validate(token, from_attributes=True)
            for token
            in deleted_tokens_db_answer
        ]

        await self.session.commit()

        return deleted_tokens

    async def logout_oidc_user(self, user_data: UserInfoFromIDProvider):
        user_db_answer = await self.get_user_by_mail(email=user_data.email)
        if not user_db_answer:
            return

        deleted_tokens = await self.delete_user_tokens(user_db_answer.id)
        return deleted_tokens

    async def logout_native_user(self, user_id: str):
        deleted_tokens = await self.delete_user_tokens(user_id)
        return deleted_tokens

    async def check_user_existence_on_native_register(
            self,
            user_data: UserCreatePlainPassword
    ):
        existing_user = await self.get_user_by_mail(email=user_data.email)
        if existing_user:
            raise AuthException(detail="User with given email already exists")

    async def register_native_user(
            self,
            user_data: UserCreateHashedPassword
    ):
        user_db_answer = await UserRepository(self.session).create(UserCreate(email=user_data.email))
        # create trial subscription by default
        sub = self.create_trial_subscription(user_db_answer.id)
        saved = await SubscriptionRepository(self.session).create(sub)

        auth_db_answer = await AuthCredentialsRepository(self.session).create(
            AuthCredentialsCreate(
                user_id=user_db_answer.id,
                auth_type=AuthType.NATIVE.value,
                password_hash=user_data.password_hash
            )
        )

        await self.session.commit()

        res = UserRead.model_validate(user_db_answer)
        # res.subscription = SubscriptionData(id=saved.id, status=saved.status,
        #                                     expiration_date=saved.expiration_date, provider=saved.provider)
        return res

    async def change_password(
            self,
            user_data: UserCreateHashedPassword
    ):
        user_db_answer = await UserRepository(self.session).create(UserCreate(email=user_data.email))
        auth_db_answer = await AuthCredentialsRepository(self.session).create(
            AuthCredentialsCreate(
                user_id=user_db_answer.id,
                auth_type=AuthType.NATIVE.value,
                password_hash=user_data.password_hash
            )
        )

        await self.session.commit()

        res = UserRead.model_validate(user_db_answer)
        # res.subscription = SubscriptionData(id=saved.id, status=saved.status,
        #                                     expiration_date=saved.expiration_date, provider=saved.provider)
        return res

    @staticmethod
    def create_trial_subscription(user_id):
        time = datetime.datetime.now() + datetime.timedelta(days=5)
        return Subscription(status='Trial', expiration_date=time, user_id=user_id)

    async def get_native_user_by_mail(
            self,
            user_data: UserCreatePlainPassword
    ):
        existing_user_db_ans = await UserRepository(self.session).get_native_user_with_creds_by_email(
            email=user_data.email
        )
        if not existing_user_db_ans:
            raise AuthException(detail="No such user in DB")

        existing_user = UserInDB(
            id=existing_user_db_ans[0].id,
            email=existing_user_db_ans[0].email,
            created_at=existing_user_db_ans[0].created_at,
            is_verified=existing_user_db_ans[0].is_verified,
            password_hash=existing_user_db_ans[1].password_hash
        )

        return existing_user

    async def update_token(
            self,
            user_id: str,
            token: str,
            token_type: str
    ):
        token_db_answer = await TokenRepository(self.session).create_or_update(
            TokenCreate(
                user_id=user_id,
                token=token,
                token_type=token_type
            )
        )
        await self.session.commit()

    async def get_refresh_token_by_user_id(self, user_id: str):
        token_db_answer = await TokenRepository(self.session).get_by_filter(
            {
                "user_id": user_id,
                "token_type": TokenType.REFRESH.value
            }
        )
        if token_db_answer:
            return token_db_answer[0].token

    async def delete_token_by_value(self, token: str):
        deleted_tokens_db_answer = await TokenRepository(self.session).delete_by_value(
            field_name="token",
            value=token
        )
        await self.session.commit()
