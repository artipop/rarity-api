from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession


from rarity_api.core.database.connector import get_session

from rarity_api.core.database.models.models import City
from rarity_api.core.database.repos.repos import CityRepository
from rarity_api.endpoints.datas import CityData

router = APIRouter(
    prefix="/cities",
    tags=["cities"]
)


def mapping(city: City) -> CityData:
    return CityData(
        id=city.id,
        name=city.name
    )


@router.get("/")
async def get_cities(
        name: str = None,
        session: AsyncSession = Depends(get_session)
) -> List[CityData]:
    repository = CityRepository(session)
    cities = await repository.get_by_filter({})
    return [mapping(city) for city in cities]
