from typing import Sequence
from uuid import UUID
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from rarity_api.common.auth.schemas.auth_credentials import AuthCredentialsCreate
from rarity_api.common.auth.schemas.token import TokenCreate
from rarity_api.common.auth.schemas.user import UserCreate
from rarity_api.common.auth.google_auth.schemas.oidc_user import UserInfoFromIDProvider
from rarity_api.core.database.models import models
from rarity_api.core.database.models.models import Country, City, Manufacturer, Region, Item, SearchHistory, Symbol, SymbolRp
from rarity_api.core.database.repos.abstract_repo import AbstractRepository


class SymbolRpRepository(AbstractRepository):
    model = models.SymbolRp

class SymbolsRepository(AbstractRepository):
    model = models.Symbol

class SymbolsLocaleRepository(AbstractRepository):
    model = models.SymbolsLocale

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

    async def verify_user(self, user_id: int):
        query = (
            update(self.model)
            .where(self.model.id == user_id)
            .values(is_verified=True)
            .returning(self.model)
        )

        result = await self._session.execute(query)
        await self._session.commit()
        return result.scalars().first()

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
            token = await self.create(**token_data.model_dump())
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
    model = Item

    async def find_items(
        self,
        page: int,
        offset: int,
        region: str | None = None,
        country: str | None = None,
        manufacturer: str | None = None,
        symbol_name: str | None = None
    ):
    # Сначала получаем список RP для символа (если передан symbol_name)
        rp_list = []
        if symbol_name:
            symbol_query = (
                select(Symbol)
                .where(Symbol.name == symbol_name)
                .options(selectinload(Symbol.rps))
            )
            symbol_result = await self._session.execute(symbol_query)
            symbols = symbol_result.scalars().all()
            
            # Собираем все RP из связанных SymbolRp
            for symbol in symbols:
                for symbol_rp in symbol.rps:
                    rp_list.append(symbol_rp.rp)
        
        # Базовый запрос с джойном производителя
        stmt = select(Item).join(Item.manufacturer).limit(offset).offset((page - 1) * offset)
        
        # Фильтрация по географии (через города производителя)
        if country or region:
            stmt = stmt.join(Manufacturer.cities).join(City.region).join(Region.country)
        if country:
            stmt = stmt.where(Country.name == country)
        if region:
            stmt = stmt.where(Region.name == region)
        
        # Фильтрация по производителю
        if manufacturer:
            stmt = stmt.where(Manufacturer.name == manufacturer)
        
        # Фильтрация по RP из символа
        if symbol_name:
            if rp_list:
                stmt = stmt.where(Item.rp.in_(rp_list))
            else:
                # Если символ не найден, возвращаем пустой результат
                stmt = stmt.where(1 == 0)  # Always false condition
        
        # Загрузка связанных данных
        stmt = stmt.options(
            selectinload(Item.manufacturer).selectinload(Manufacturer.cities)
        )
        
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def find_by_id(self, _id: int):
        s = select(Item).where(Item.id == _id).join(Manufacturer.cities).join(City.region).join(Region.country)
        result = await self._session.execute(s)
        return result.scalars().first()
        # TODO: join country(name) + region(name) + city(name) + manufacturer(name)

    async def find_by_book_ids(self, ids: list[int]) -> Sequence[Item]:
        s = select(Item)
        if ids:
            s = s.where(Item.rp.in_(ids))
            result = await self._session.execute(s)
            return result.scalars().all()
        else:
            return []

    async def find_by_book_id(self, book_id: int) -> Item | None:
        s = select(Item).where(Item.rp == book_id)
        result = await self._session.execute(s)
        return result.scalars().first()

class SearchHistoryRepository(AbstractRepository):
    model = SearchHistory

    async def create(self, search_history):
        self._session.add(search_history)
        await self._session.commit()
        await self._session.refresh(search_history)

    async def find_last(self) -> Sequence[SearchHistory]:
        s = select(SearchHistory).order_by(SearchHistory.created_at.desc()).limit(10)
        result = await self._session.execute(s)
        return result.scalars().all()

    async def find_by_id(self, _id: int) -> SearchHistory | None:
        s = select(SearchHistory).where(SearchHistory.id == _id)
        result = await self._session.execute(s)
        return result.scalars().first()
