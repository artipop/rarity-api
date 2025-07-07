import asyncio
from pprint import pprint
from typing import Union
import openpyxl
import os
from pydantic import BaseModel
from sqlalchemy import insert
from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import Item
from rarity_api.core.database.repos.repos import CityRepository, CountryRepository, ItemRepository, ManufacturerCityRepository, ManufacturerRepository, RegionRepository


class ReadItem(BaseModel):
    rp: int | None
    country: str | None
    manufacturer_name: str | None
    region: str | None
    city: str | None
    prod_year_start: int | None
    prod_year_end: Union[int, str] | None
    desc: str | None


async def main():
    async for session in get_session():
        path = os.path.join(os.path.dirname(__file__), 'excels\\processed_porcelain_marks_final.xlsx')

        workbook = openpyxl.load_workbook(path)
        sheet = workbook.active

        for row in sheet.iter_rows(min_row=10, values_only=True):
            current_row = ReadItem(
                rp=row[0],
                country=row[1],
                manufacturer_name=row[2],
                region=row[3],
                city=row[4],
                prod_year_start=row[5],
                prod_year_end=row[6],
                desc=row[7]
            )

            print(current_row)


            country_repository = CountryRepository(session)
            city_repository = CityRepository(session)
            region_repository = RegionRepository(session)
            manufacturer_repository = ManufacturerRepository(session)

            item_repository = ItemRepository(session)
            manufacturer_city_repository = ManufacturerCityRepository(session)
            country = await country_repository.get_or_create(name=current_row.country)
            print(country)

            region = await region_repository.get_or_create(name=current_row.region, country_id=country.id)
            city = await city_repository.get_or_create(name=current_row.city, region_id=region.id if region else None)
            manufacturer = await manufacturer_repository.get_or_create(name=current_row.manufacturer_name)
            manufacturer_city = await manufacturer_city_repository.get_or_create(manufacturer_id=manufacturer.id, city_id=city.id)

            item = await item_repository.create(
                rp=current_row.rp,
                manufacturer_id=manufacturer.id,
                description=current_row.desc,
                production_years=f"{current_row.prod_year_start} - {current_row.prod_year_end if current_row.prod_year_end else "now"}"
            )

if __name__ == "__main__":
    asyncio.run(main())

