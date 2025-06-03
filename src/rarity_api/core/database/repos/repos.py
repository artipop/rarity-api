from typing import Sequence
from uuid import UUID
from sqlalchemy import select
from rarity_api.common.auth.schemas.auth_credentials import AuthCredentialsCreate
from rarity_api.common.auth.schemas.token import TokenCreate
from rarity_api.common.auth.schemas.user import UserCreate
from rarity_api.common.auth.google_auth.schemas.oidc_user import UserInfoFromIDProvider
from rarity_api.core.database.models import models
from rarity_api.core.database.models.models import Country, City, Manufacturer, Region
from rarity_api.core.database.repos.abstract_repo import AbstractRepository

class SubscriptionRepository(AbstractRepository):
    model = models.Subscription

    async def create(self, obj):
        self._session.add(obj)
        await self._session.commit()
        await self._session.refresh(obj)

    async def update(self, obj):
        self._session.add(obj)
        await self._session.commit()
        await self._session.refresh(obj)

    async def find_by_user(self, user_id: UUID) -> models.Subscription | None:
        sel = (select(models.Subscription).where(models.Subscription.user_id == user_id))
        result = await self._session.execute(sel)
        return result.scalars().first()

class UserRepository(AbstractRepository):
    model = models.User

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
            select(self.model, models.AuthCredentials)
            .where(self.model.email == email)
            .join(self.model.auth_credentials)
        )

        result = await self._session.execute(query)
        return result.first()

class CountryRepository(AbstractRepository):
    model = Country

    async def find_by_filter(self, name: str) -> Sequence[Country]:
        s = select(Country)
        if name:
            s = s.where(Country.name.icontains(name))
        result = await self._session.execute(s)
        return result.scalars().all()


class AuthCredentialsRepository(AbstractRepository):
    model = models.AuthCredentials

    async def get_or_create(self, auth_data: AuthCredentialsCreate):
        existing_auth_data = await self.get_by_filter({"user_id": auth_data.user_id})

        if existing_auth_data:
            return existing_auth_data[0]
        else:
            created_auth_data = await self.create(auth_data)
            return created_auth_data

class TokenRepository(AbstractRepository):
    model = models.Token

    async def create_or_update(self, token_data: TokenCreate):
        existing_token_data = await self.get_by_filter(
            {
                "user_id": token_data.user_id,
                "token_type": token_data.token_type
            }
        )

        if existing_token_data:
            token: models.Token = existing_token_data[0]
            token.token = token_data.token
        else:
            token = await self.create(token_data)
            self._session.add(token)


class RegionRepository(AbstractRepository):
    model = Region

    async def find_by_filter(self, name: str) -> Sequence[Region]:
        s = select(Region)
        if name:
            s = s.where(Region.name.icontains(name))
        result = await self._session.execute(s)
        return result.scalars().all()

    async def get_or_create(self, **kwargs):
        if not kwargs.get("name", None):
            return None

        query = (
            select(self.model)
            .filter_by(**kwargs)
        )

        result = await self._session.execute(query)
        obj = result.scalars().first()

        if obj is None:
            obj = await self.create(**kwargs)
            await self._session.commit()
        return obj

class CityRepository(AbstractRepository):
    model = City

    async def find_by_filter(self, name: str) -> Sequence[City]:
        s = select(City)
        if name:
            s = s.where(City.name.icontains(name))
        result = await self._session.execute(s)
        return result.scalars().all()


class ManufacturerRepository(AbstractRepository):
    model = Manufacturer

    async def find_by_filter(self, name: str) -> Sequence[Manufacturer]:
        s = select(Manufacturer)
        if name:
            s = s.where(Manufacturer.name.icontains(name))
        result = await self._session.execute(s)
        return result.scalars().all()


class ItemRepository(AbstractRepository):
    model = models.Item

class SearchHistoryRepository(AbstractRepository):
    model = models.SearchHistory