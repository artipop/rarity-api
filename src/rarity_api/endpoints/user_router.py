from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from sqlalchemy import or_, select

from rarity_api.common.auth.native_auth.dependencies import authenticate
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import User
from sqlalchemy.ext.asyncio import AsyncSession

from rarity_api.core.database.repos.repos import UserRepository
from rarity_api.endpoints.datas import UpdateUser

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.get("/subcription", summary="Получить подписку пользователя")
async def get_user_subscription(request: Request, user: UserRead = Depends(authenticate)):
    return user

@router.get("/search")
async def search_users(page: int, offset: int = 20, name: Optional[str] = None, email: Optional[str] = None, session: AsyncSession = Depends(get_session)): # если надо будет, админ авторизацию прикрутить можно
    
    filters = []

    if name is not None:
        filters.append(User.first_name.icontains(name))
    if email is not None:
        filters.append(User.email.icontains(email))

    query = (
        select(User)
        .where(or_(*filters))
        .offset((page - 1) * offset)
        .limit(offset)
    )
    result = await session.execute(query)
    return result.scalars().all()


@router.delete("/delete/{user_id}")
async def delete_user(user_id: UUID, session: AsyncSession = Depends(get_session)):
    return await UserRepository(session).delete_by_id(user_id)

@router.put("/{user_id}")
async def update_user(user_id: UUID, update_data: UpdateUser, session: AsyncSession = Depends(get_session)):
    return await UserRepository(session).update_by_id(user_id, **update_data.model_dump())