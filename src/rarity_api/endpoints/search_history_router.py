from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from rarity_api.endpoints.datas import SearchHistoryData

from rarity_api.core.database.connector import get_session
from rarity_api.core.database.repos.repos import SearchHistoryRepository

router = APIRouter(
    prefix="/search_history",
    tags=["search_history"]
)


@router.get("/", response_model=List[SearchHistoryData])
async def get_history(
        session: AsyncSession = Depends(get_session)
) -> List[SearchHistoryData]:
    repository = SearchHistoryRepository(session)
    history = await repository.find_last()
    return [mapping(item) for item in history]


@router.get("/{item_id}", response_model=SearchHistoryData)
async def get_history_by_id(
        item_id: int,
        session: AsyncSession = Depends(get_session),
) -> SearchHistoryData:
    repository = SearchHistoryRepository(session)
    item = await repository.find_by_id(item_id)
    return mapping(item) if item else None


def mapping(item):
    return SearchHistoryData(
        id=item.id,
        region_name=item.region_name,
        country_name=item.country_name,
        manufacturer_name=item.manufacturer_name,
        created_at=item.created_at
    )
