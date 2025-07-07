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
from rarity_api.core.database.models.models import Country, Item, Manufacturer, ManufacturerCity, SearchHistory, City, Region, Symbol, SymbolsLocale
from rarity_api.core.database.repos.repos import ItemRepository, ManufacturerRepository, SearchHistoryRepository
from rarity_api.settings import settings

router = APIRouter(
    prefix="/items",
    tags=["items"]
)


@router.post("/create")
async def create_item(create_data: CreateItem, session: AsyncSession = Depends(get_session)):
    manufacturer = await ManufacturerRepository(session).find_by_name(create_data.manufacturer)
    if not manufacturer:
        raise HTTPException(
            status_code=404,
            detail="Мануфактура не найдена"
        )
    data_dict = create_data.model_dump()
    data_dict.pop("manufacturer")
    data_dict.pop("region")
    data_dict.pop("year_from")
    data_dict.pop("year_to")
    data_dict["production_years"] = f"{'' if create_data.year_from is None else create_data.year_from}-{'' if create_data.year_to is None else create_data.year_to}"
    return await ItemRepository(session).create(**data_dict, manufacturer_id=manufacturer.id)


@router.put("/{item_id}")
async def update_item(
        item_id: int,
        data: CreateItem,
        session: AsyncSession = Depends(get_session),
        # TODO: uncomment later
        # user: UserRead = Depends(authenticate)
):
    repository = ItemRepository(session)
    item = await repository.find_by_id(item_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail="Клеймо не найдено"
        )
    if data.manufacturer:
        manufacturer = await ManufacturerRepository(session).find_by_name(data.manufacturer)
        if not manufacturer:
            raise HTTPException(
                status_code=404,
                detail="Мануфактура не найдена"
            )
        item.manufacturer_id = manufacturer.id
    item.rp = data.rp
    item.description = data.description
    item.production_years = data.production_years
    item.photo_links = data.photo_links
    # item.region = data.region
    item.source = data.source
    await session.commit()
    await session.refresh(item)
    return mapping(item)


@router.delete("/{item_id}")
async def delete_item(
        item_id: int,
        session: AsyncSession = Depends(get_session),
        # TODO: uncomment later
        # user: UserRead = Depends(authenticate)
):
    repository = ItemRepository(session)
    await repository.delete_by_id(item_id)
    return Response(status_code=200)


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


@router.get("/length")
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
):
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
    all_items_query = (
        select(Item)
    )
    all_items_result = await session.execute(all_items_query)
    all_items = all_items_result.scalars().all()
    return {
        "count": len(items),
        "pages": len(all_items) // offset
    }

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
): # -> ItemFullData:
    repository = ItemRepository(session)
    query = (
        select(Item)
        .where(Item.id == item_id)
        .options(
            selectinload(Item.manufacturer)
            .selectinload(Manufacturer.cities)
            .selectinload(ManufacturerCity.city)
            .selectinload(City.region)
            .selectinload(Region.country)
        )
    )
    result = await session.execute(query)
    item = result.scalars().first()
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
        page: int = 1,
        offset: int = 10,
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        symbol_name: str = None,
        session: AsyncSession = Depends(get_session)
):
    response = requests.post(
        # TODO: use env for llm URL
        'http://host.docker.internal:8080/recognize',
        json={'image': data.base64}
    )
    if response.status_code != 200:
        return Response(status_code=response.status_code)
    data = response.json()
    if data['status'] != 'success':
        return Response(status_code=400)
    results = data['results'] if data['results'] else []
    sorted_by_similarity = sorted(results, key=lambda d: d['similarity'], reverse=True)
    start = (page - 1) * offset
    end = start + offset
    paginated_results = sorted_by_similarity[start:end]
    repository = ItemRepository(session)
    book_ids: list[int] = [
        int(result['template'].split('/')[-1].split('_')[1].split('.')[0])
        for result in paginated_results
    ]
    print(book_ids)
    items = await repository.find_items(page, offset,
                                        region=region_name, country=country_name, manufacturer=manufacturer_name,
                                        symbol_name=symbol_name,
                                        book_ids=book_ids)
    return [mapping(item) for item in items]


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
        image=f"{item.rp}" if item.rp else None,
        source=item.source
    )

def full_mapping(item: Item): # -> ItemFullData:
    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)
    print(item.manufacturer.cities)

    cities = [manufacturer_city.city.name for manufacturer_city in item.manufacturer.cities]
    regions = [manufacturer_city.city.region.name for manufacturer_city in item.manufacturer.cities]
    countries = [manufacturer_city.city.region.country.name for manufacturer_city in item.manufacturer.cities]

    print(f"cities -- {cities}, regions - {regions}, counties - {countries}")

    return ItemFullData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{item.rp}" if item.rp else None,
        region=item.region.name if item.region else "",
        country=item.country.name if item.country else "",
        city=item.city.name if item.city else "",
        regions=regions,
        countries=countries,
        cities=cities,
        manufacturer=item.manufacturer.name if item.manufacturer else None
    )
