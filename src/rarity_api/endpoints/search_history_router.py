from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from rarity_api.endpoints.datas import SearchHistoryData, SearchHistoryCreate

from rarity_api.core.database.connector import get_session
from rarity_api.core.database.repos.repos import SearchHistoryRepository

router = APIRouter(
    prefix="/search_history",
    tags=["search_history"]
)


@router.get("/", response_model=List[SearchHistoryData])
async def get_search_history(
        session: AsyncSession = Depends(get_session)
) -> List[SearchHistoryData]:
    repository = SearchHistoryRepository(session)
    history = await repository.get_by_filter({})
    return [SearchHistoryData(
        id=item.id,
        region_name=item.region_name,
        country_name=item.country_name,
        manufacturer_name=item.manufacturer_name,
        created_at=item.created_at
    ) for item in history]
