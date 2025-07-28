import hashlib
from typing import List, Annotated

import cachetools
import requests
from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response
from sqlalchemy.orm import selectinload
from rarity_api.common.auth.dependencies import authenticate
from rarity_api.common.auth.schemas.user import UserRead
from rarity_api.endpoints.datas import CreateItem, ItemData, SearchHistoryCreate, ItemFullData, FindByImageData, SearchResponse
from rarity_api.endpoints.datas import ItemData, SearchHistoryCreate, ItemFullData, FindByImageData, SearchResponse

from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import City, Country, Item, Manufacturer, ManufacturerCity, Region, SearchHistory, Symbol, SymbolsLocale
from rarity_api.core.database.repos.repos import ItemRepository, ManufacturerRepository, SearchHistoryRepository
from rarity_api.settings import settings

from src.rarity_api.core.database.repos.repos import UserFavouritesRepository

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
    # TODO: пофиксить... чтобы не получалось " - " или "100 - " или " - 100"
    data_dict["production_years"] = f"{'' if create_data.year_from is None else create_data.year_from} - {'' if create_data.year_to is None else create_data.year_to}"
    return await ItemRepository(session).create(**data_dict, manufacturer_id=manufacturer.id)


@router.get("/favourites")
async def list_favourites(
        session: AsyncSession = Depends(get_session),
        user: UserRead = Depends(authenticate)
) -> List[ItemData]:
    print(type(user))
    user_id = user.id
    repository = UserFavouritesRepository(session)
    favs = await repository.get_user_fav_by_filter(user_id=user_id)
    repository = ItemRepository(session)
    items = [await repository.find_by_id(fav.item_id) for fav in favs]
    return [mapping(item, True) for item in items]


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
#    item.production_years = data.production_years
    # TODO: пофиксить... чтобы не получалось " - " или "100 - " или " - 100"
    item.production_years = f"{'' if data.year_from is None else data.year_from} - {'' if data.year_to is None else data.year_to}"
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
async def items_length(
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        symbol_name: str = None,
        # from_date: str = None,
        # to_date: str = None,
        session: AsyncSession = Depends(get_session)
):
    repository = ItemRepository(session)
    items = await repository.find_items(page=None, offset=None, region=region_name, country=country_name, manufacturer=manufacturer_name, symbol_name=symbol_name)
    return {
        "total": len(items),
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
    # item = await repository.find_by_id(item_id)
    print(item)
    if not item:
        return Response(status_code=404)
    return full_mapping(item)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.put("/{item_id}/markfav")
async def mark_favourite(
        item_id: int,
        # token: Annotated[str, Depends(oauth2_scheme)],
        session: AsyncSession = Depends(get_session),
        user: UserRead = Depends(authenticate)
) -> ItemData:
    # print(token)
    user_id = user.id
    repository = UserFavouritesRepository(session)
    item_repo = ItemRepository(session)
    item = await item_repo.find_by_id(item_id)
    if not item:
        raise HTTPException(
            status_code=400,
            detail="Item not found"
        )

    fav_row = await repository.get_user_fav_by_filter(user_id=user_id, item_id=item_id)
    if fav_row:
        await repository.mark_unfav(item_id=item_id, user_id=user_id)

    else:
        await repository.create(user_id=user_id, item_id=item_id)

    return mapping(item)


cache = cachetools.TTLCache(maxsize=1000, ttl=300)


@router.post("/find_by_image")
async def find_by_image(
        base64: str = Form(...),
        page: int = 1,
        offset: int = 10,
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        symbol_name: str = None,
        session: AsyncSession = Depends(get_session)
):
    if not base64:
        raise HTTPException(
            status_code=422,
            detail="Field 'base64' is required and must be a string"
        )
    key = get_cache_key(base64)

    if key not in cache:
        # Вызов нейросети только если нет в кеше
        response = requests.post(
            # TODO: use env for llm URL
            'http://host.docker.internal:8505/recognize',
            json={'image': base64}
        )
        if response.status_code != 200:
            return Response(status_code=response.status_code)
        data = response.json()
        if data['status'] != 'success':
            return Response(status_code=400)
        cache[key] = data['results'] if data['results'] else []

    results = cache[key]
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


@router.post("/find_by_image/length")
async def find_by_image_len(
        base64: str = Form(...),
        region_name: str = None,
        country_name: str = None,
        manufacturer_name: str = None,
        symbol_name: str = None,
        session: AsyncSession = Depends(get_session)
):
    if not base64:
        raise HTTPException(
            status_code=422,
            detail="Field 'base64' is required and must be a string"
        )
    key = get_cache_key(base64)

    if key not in cache:
        # Вызов нейросети только если нет в кеше
        response = requests.post(
            # TODO: use env for llm URL
            'http://host.docker.internal:8505/recognize',
            json={'image': base64}
        )
        if response.status_code != 200:
            return Response(status_code=response.status_code)
        data = response.json()
        if data['status'] != 'success':
            return Response(status_code=400)
        cache[key] = data['results'] if data['results'] else []

    results = cache[key]
    repository = ItemRepository(session)
    book_ids: list[int] = [
        int(result['template'].split('/')[-1].split('_')[1].split('.')[0])
        for result in results
    ]
    print(book_ids)
    items = await repository.find_items(page=None, offset=None,
                                        region=region_name, country=country_name, manufacturer=manufacturer_name,
                                        symbol_name=symbol_name,
                                        book_ids=book_ids)
    return {
        "total": len(items),
    }


def mapping(item: Item, fav: bool = False) -> ItemData:
    years_array = item.production_years.split(" - ")
#    years_end = int(years_array[1]) if (len(years_array > 0 and years_array[1] != "now") else 0
    years_end = int(years_array[1].strip()) if (years_array[1] != "now") else 0

    return ItemData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{item.rp}" if item.rp else None,
        source=item.source,
        is_favourite=fav
    )

def full_mapping(item: Item): # -> ItemFullData:
    years_array = item.production_years.split(" - ")
    years_end = int(years_array[1] if years_array[1] != "now" else 0)
    print(item.manufacturer.cities)

    cities = [manufacturer_city.city.name for manufacturer_city in item.manufacturer.cities]
#    regions = [manufacturer_city.city.region.name for manufacturer_city in item.manufacturer.cities]
#    countries = [manufacturer_city.city.region.country.name for manufacturer_city in item.manufacturer.cities]

    regions = []
    countries = []

    if item.manufacturer:
        for mc in item.manufacturer.cities:
            city = mc.city
            if city:
                region = city.region
                if region:
                    regions.append(region.name)
                    country = region.country
                    if country:
                        countries.append(country.name)

    print(f"cities -- {cities}, regions - {regions}, counties - {countries}")

    return ItemFullData(
        id=item.id,
        rp=item.rp,
        name=item.name,
        description=item.description,
        year_from=int(years_array[0] if years_array[0] != "None" else 0),
        year_to=years_end,
        image=f"{item.rp}" if item.rp else None,
        region=regions[0] if regions else "",
        country=countries[0] if countries else "",
        city=cities[0] if cities else "",
#        region=item.region.name if item.region else "",
#        country=item.country.name if item.country else "",
#        city=item.city.name if item.city else "",
#        regions=regions,
#        countries=countries,
        regions=list(set(regions)),
        countries=list(set(countries)),
        cities=cities,
        manufacturer=item.manufacturer.name if item.manufacturer else None
    )


def get_cache_key(image_base64: str) -> str:
    return hashlib.sha256(image_base64.encode()).hexdigest()
