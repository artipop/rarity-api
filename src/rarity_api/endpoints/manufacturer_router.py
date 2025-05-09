from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from rarity_api.endpoints.datas import ManufacturerData, CityData

# refactored 
from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import Manufacturer
from rarity_api.core.database.repos.repos import ManufacturerRepository

router = APIRouter(
    prefix="/manufacturers",
    tags=["manufacturers"]
)


def mapping(manufacturer: Manufacturer) -> ManufacturerData:
    return ManufacturerData(
        id=manufacturer.id,
        name=manufacturer.name,
        cities=[CityData(id=city.id, name=city.name) for city in manufacturer.cities]
    )

@router.get("/")
async def get_manufacturers(
        name: str = None,
        session: AsyncSession = Depends(get_session)
) -> List[ManufacturerData]:
    repository = ManufacturerRepository(session)
    manufacturers = await repository.get_by_filter({})
    return [mapping(manufacturer) for manufacturer in manufacturers]
