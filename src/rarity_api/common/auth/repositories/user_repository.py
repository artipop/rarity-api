from sqlalchemy import select

from rarity_api.common.auth.providers.schemas.oidc_user import UserInfoFromIDProvider
from rarity_api.common.auth.schemas.user import UserCreate
from rarity_api.core.database.models.models import AuthCredentials
from rarity_api.core.database.models.models import User
from rarity_api.core.database.repos.abstract_repo import AbstractRepository


class UserRepository(AbstractRepository):
    model = User

    async def get_existing_user_by_mail(self, email: str):
        existing_user = await self.get_by_filter({"email": email})
        if existing_user:
            return existing_user[0]

    async def get_or_create_oidc_user(self, user_data: UserInfoFromIDProvider):
        existing_user = await self.get_existing_user_by_mail(email=user_data.email)
        if existing_user:
            return existing_user

        created_user = await self.create(UserCreate(email=user_data.email))

        return created_user

    async def get_native_user_with_creds_by_email(self, email: str):
        query = (
            select(self.model, AuthCredentials)
            .where(self.model.email == email)
            .join(self.model.auth_credentials)
        )

        result = await self._session.execute(query)
        return result.first()
