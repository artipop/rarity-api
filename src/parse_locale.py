import asyncio
from pprint import pprint
from typing import Optional, Union
import openpyxl
import os
from pydantic import BaseModel
from sqlalchemy import insert, select
from rarity_api.core.database.connector import get_session
from rarity_api.core.database.models.models import Item, Symbol
from rarity_api.core.database.repos.repos import CityRepository, CountryRepository, ItemRepository, ManufacturerRepository, RegionRepository, SymbolsLocaleRepository


class ReadLocale(BaseModel):
    translit: Optional[str]
    locale_de: Optional[str]
    locale_ru: Optional[str]
    locale_en: Optional[str]


async def main():
    async for session in get_session():
        path = os.path.join(os.path.dirname(__file__), 'excels\\symbol_phrases_translated_complete.xlsx')

        workbook = openpyxl.load_workbook(path)
        sheet = workbook.active

        for row in sheet.iter_rows(min_row=2, values_only=True):
            current_row = ReadLocale(
                translit=row[0],
                locale_de=row[1],
                locale_ru=row[2],
                locale_en=row[3]
                
            )
            
            symbol_query = (
                select(Symbol)
                .where(Symbol.name == current_row.locale_de)
            )

            result = await session.execute(symbol_query)
            symbol = result.scalars().first()
            if hasattr(symbol, 'id'):
                locale = await SymbolsLocaleRepository(session).get_or_create(symbol_id=symbol.id,translit=current_row.translit, locale_de=current_row.locale_de, locale_ru=current_row.locale_ru, locale_en=current_row.locale_en)

if __name__ == "__main__":
    asyncio.run(main())

