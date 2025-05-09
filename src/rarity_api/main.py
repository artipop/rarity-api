from contextlib import asynccontextmanager

from alembic import command
from alembic.config import Config
from fastapi import FastAPI

from rarity_api.common.http_client import HttpClient
from rarity_api.endpoints.city_router import router as city_router
from rarity_api.endpoints.country_router import router as country_router
from rarity_api.endpoints.item_router import router as item_router
from rarity_api.endpoints.manufacturer_router import router as manufacturer_router
from rarity_api.endpoints.region_router import router as region_router
from rarity_api.endpoints.search_history_router import router as search_history_router
from rarity_api.common.auth.google_auth.router import router as google_auth_router
from rarity_api.common.auth.google_auth.utils.id_provider_certs import IdentityProviderCerts
from rarity_api.common.auth.native_auth.router import router as plain_auth_router

app = FastAPI(
    title="Rarity API",
    description="API for managing porcelain rarity data",
    version="1.0.0"
)

app.include_router(google_auth_router)
app.include_router(plain_auth_router)
# Include all routers
app.include_router(country_router)
app.include_router(region_router)
app.include_router(city_router)
app.include_router(manufacturer_router)
app.include_router(item_router)
app.include_router(search_history_router)


@asynccontextmanager
async def lifespan():
    http_client = HttpClient()
    await http_client.init_session()
    await IdentityProviderCerts().renew_certs()
    run_migrations()
    yield
    await http_client.close_session()


def run_migrations():
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
