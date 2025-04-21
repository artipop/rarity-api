from uuid import UUID

from rarity_api.database import AbstractRepository
from rarity_api.subs.models import Subscription
from sqlalchemy import select


class SubscriptionRepository(AbstractRepository):
    model = Subscription

    async def create(self, obj):
        self._session.add(obj)
        await self._session.commit()
        await self._session.refresh(obj)

    async def update(self, obj):
        self._session.add(obj)
        await self._session.commit()
        await self._session.refresh(obj)

    async def find_by_user(self, user_id: UUID) -> Subscription | None:
        sel = (select(Subscription).where(Subscription.user_id == user_id))
        result = await self._session.execute(sel)
        return result.scalars().first()
