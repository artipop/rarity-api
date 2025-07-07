from typing import List

import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response
from sqlalchemy.orm import selectinload
from rarity_api.common.auth.native_auth.dependencies import authenticate
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.endpoints.datas import CreateItem, ItemData, SearchHistoryCreate, ItemFullData, FindByImageData, SearchResponse
from rarity_api.endpoints.datas import ItemData, SearchHistoryCreate, ItemFullData, FindByImageData, SearchResponse

from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import Country, Item, Manufacturer, SearchHistory, Symbol, SymbolsLocale
from rarity_api.core.database.repos.repos import ItemRepository, ManufacturerRepository, SearchHistoryRepository
from rarity_api.settings import settings

router = APIRouter(
    prefix="/items",
    tags=["items"]
)


@router.post("/create")
async def create_item(create_data: CreateItem, session: AsyncSession = Depends(get_session), user: UserRead = Depends(authenticate)):
    manufacturer: Manufacturer = await ManufacturerRepository(session).get_one_by_filter(create_data.manufacturer)
    if not manufacturer:
        raise HTTPException(
            status_code=400,
            detail="Мануфактурер не найден."
        )
    return await ItemRepository(session).create(**create_data.model_dump().pop("manufacturer"), manufacturer_id=manufacturer.id)

@router.get("/")
async def get_items(
        page: int = 1,
        offset: int = 50,
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        symbol_name: str = None,
        # from_date: str = None,
        # to_date: str = None,
        session: AsyncSession = Depends(get_session)
) -> List[ItemData]:
    # Save search history
    # TODO: если идентичный поиск уже был, то обновить дату поиска просто (поднять вверх по сути)
    search_history = SearchHistory(
        region_name=region_name if region_name else "",
        country_name=country_name,
        manufacturer_name=manufacturer_name
    )
    history_repository = SearchHistoryRepository(session)
    await history_repository.create(search_history)
    repository = ItemRepository(session)
    items = await repository.find_items(page, offset, region=region_name, country=country_name, manufacturer=manufacturer_name, symbol_name=symbol_name)
    return [mapping(item) for item in items]


#@router.get("/{item_id}")
#async def get_item(
#        item_id: int,
#        session: AsyncSession = Depends(get_session)
#) -> ItemFullData:
#    repository = ItemRepository(session)
#    item = await repository.find_by_id(item_id)
#    if not item:
#        return Response(status_code=404)
#    return full_mapping(item)


@router.get("/search", response_model=None)
async def find_symbols(
        query: str = None,
        session: AsyncSession = Depends(get_session),
) -> SearchResponse:
    country_query = (
        select(Country.name)
#        .where(Country.name.ilike(f"%{query}%"))
        .where(Country.name.icontains(query))
    )

    manufacturer_query = (
        select(Manufacturer.name)
#        .where(Manufacturer.name.ilike(f"%{query}%"))
        .where(Manufacturer.name.icontains(query))
    )

    symbol_query = (
        select(SymbolsLocale)
        .join(Symbol, Symbol.id == SymbolsLocale.symbol_id)
        .where(or_(
            SymbolsLocale.locale_de.icontains(query),
            SymbolsLocale.locale_en.icontains(query),
            SymbolsLocale.locale_ru.icontains(query),
            SymbolsLocale.translit.icontains(query)

        ))
        .options(selectinload(SymbolsLocale.symbol))
    )

    country_result = await session.execute(country_query)
    manufacturer_result = await session.execute(manufacturer_query)
    symbol_result = await session.execute(symbol_query)

    countries = country_result.scalars().all()
    manufacturers = manufacturer_result.scalars().all()
    symbols_locale: SymbolsLocale = symbol_result.scalars().all()
    return SearchResponse(
        countries=countries,
        manufacturers=manufacturers,
        symbols=[symbol.symbol.name for symbol in symbols_locale]
    )


# @router.get("/search")
# async def find_symbols(
#         query: str = None,
#         session: AsyncSession = Depends(get_session)
# ) -> SearchResponse:
#     return SearchResponse(countries=[], manufacturers=[], symbols=[])


@router.get("/{item_id}")
async def get_item(
        item_id: int,
        session: AsyncSession = Depends(get_session)
) -> ItemFullData:
    repository = ItemRepository(session)
    item = await repository.find_by_id(item_id)
    print(item)
    if not item:
        return Response(status_code=404)
    return full_mapping(item)
#    return full_mapping(item)


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


@router.post("/find_by_image")
async def find_by_image(
        data: FindByImageData,
        session: AsyncSession = Depends(get_session)
):
    response = requests.post(
        # TODO: use env for llm URL
        'http://158.255.6.121:8080/recognize',
        json={'image': data.base64}
    )
    print(response.status_code)
    if response.status_code != 200:
        return Response(status_code=response.status_code)
    data = response.json()
    print(data['status'])
#    print(response.status_code)
    if data['status'] != 'success':
        return Response(status_code=400)
    results = data['results'] if data['results'] else []
    sorted_by_similarity = sorted(results, key=lambda d: d['similarity'], reverse=True)
    sorted_by_similarity = sorted(results, key=lambda d: d['similarity'], reverse=True)
    print(sorted_by_similarity)
    repository = ItemRepository(session)
    a = []
    for result in sorted_by_similarity:
        i = int(result['template'].split('/')[-1].split('_')[1].split('.')[0])
        item = await repository.find_by_book_id(i)
        if item:
            item_data = mapping(item)
            a.append(item_data)
    return a


def mapping(item: Item) -> ItemData:
    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)

    return ItemData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{settings.api_base_url}/images/mark_{item.rp}.png" if item.rp else None,
    )

def full_mapping(item) -> ItemFullData:
    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)

    return ItemFullData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{settings.api_base_url}/images/mark_{item.rp}.png" if item.rp else None,
        region=item.region.name if item.region else "",
        country=item.country.name if item.country else "",
        city=item.city.name if item.city else "",
        manufacturer=item.manufacturer.name if item.manufacturer else "",
    )

def full_mapping(item) -> ItemFullData:
    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)

    return ItemFullData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{settings.api_base_url}/images/mark_{item.rp}.png" if item.rp else None,
        region="",
        country="",
        city="",
        manufacturer="",
    )
