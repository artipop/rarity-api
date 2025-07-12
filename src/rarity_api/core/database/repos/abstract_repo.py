from abc import ABC
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import (
    insert,
    select,
    update,
    delete
)

class AbstractRepository(ABC):
    def __init__(self, session: AsyncSession):
        self._session = session

    model = None

    # async def commit(self):
    #     try:
    #         await self._session.commit()
    #     except SQLAlchemyError as e:
    #         await self._session.rollback()
    #         raise e
    #
    # def rollback(self):
    #     self._session.rollback()
    #
    async def get_by_id(self, _id):
        return await self._session.get(self.model, _id)
    #
    # async def get_all(self):
    #     result = await self._session.execute(select(self.model))
    #     return result.scalars().all()

    async def create(self, **kwargs):
        
        query = insert(self.model).values(**kwargs).returning(self.model)
        result = await self._session.execute(query)
        await self._session.commit()
        return result.scalars().first()

    # async def update_one(self, _id, obj):
    #     query = update(self.model).where(self.model.id == _id).values(**obj.model_dump()).returning(self.model)
    #     result = await self._session.execute(query)
    #     await self._session.commit()
    #     return result.scalars().first()
    #
    async def delete_by_id(self, _id):
        query = delete(self.model).where(self.model.id == _id)
        result = await self._session.execute(query)
        await self._session.commit()
        return result.rowcount

    async def get_by_filter(self, kwargs):
        query = select(self.model).filter_by(**kwargs)
        result = await self._session.execute(query)
        return result.scalars().all()

    async def get_one_by_filter(self, **kwargs):
        query = select(self.model).filter_by(**kwargs)
        result = await self._session.execute(query)
        return result.scalars().one_or_none()
    
    async def get_or_create(self, **kwargs):
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

    async def update_by_id(self, objId: int, **kwargs):
        query = (
            update(self.model)
            .where(self.model.id == objId)
            .values(**kwargs)
            .returning(self.model)

        )

        result = await self._session.execute(query)
        await self._session.commit()
        return result.scalars().first()

    # async def delete_by_value(self, field_name, value):
    #     field = getattr(self.model, field_name)
    #     stmt = delete(self.model).where(field == value).returning(self.model)
    #     result = await self._session.execute(stmt)
    #     return result.scalars().all()