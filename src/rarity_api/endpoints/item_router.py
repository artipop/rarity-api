from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from rarity_api.endpoints.datas import ItemData, SearchHistoryCreate, ItemFullData

from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import Item, SearchHistory
from rarity_api.core.database.repos.repos import ItemRepository, SearchHistoryRepository

router = APIRouter(
    prefix="/items",
    tags=["items"]
)


@router.get("/")
async def get_items(
        page: int = 1,
        offset: int = 50,
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        # from_date: str = None,
        # to_date: str = None,
        session: AsyncSession = Depends(get_session)
) -> List[ItemData]:
    # Save search history
    search_history = SearchHistory(
        region_name=region_name,
        country_name=country_name,
        manufacturer_name=manufacturer_name
    )
    history_repository = SearchHistoryRepository(session)
    await history_repository.create(search_history)
    repository = ItemRepository(session)
    items = await repository.find_items(page, offset, region=region_name, country=country_name, manufacturer=manufacturer_name)
    return [mapping(item) for item in items]


@router.get("/{item_id}")
async def get_item(
        item_id: int,
        session: AsyncSession = Depends(get_session)
) -> ItemFullData:
    repository = ItemRepository(session)
    item = await repository.find_by_id(item_id)
    if not item:
        return Response(status_code=404)
    return mapping(item)



@router.put("/{item_id}/markfav")
async def mark_favourite(
        item_id: int,
        session: AsyncSession = Depends(get_session)
) -> ItemData:
    repository = ItemRepository(session)
    item = await repository.find_by_id(item_id)
    if not item:
        return Response(status_code=404)
    return mapping(item)


@router.get("/favourites")
async def list_favourites(
        session: AsyncSession = Depends(get_session)
) -> List[ItemData]:
    repository = ItemRepository(session)
    # ...
    # return [mapping(item) for item in items]


def mapping(item: Item) -> ItemData:

    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)
    print(years_array)

    return ItemData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end
        # image=item.photo_links
    )
